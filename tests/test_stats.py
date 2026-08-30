"""Reine Berechnungen für `dmarcwatch stats` (report.py) - Tagestrend und
Verschärfungs-Einschätzung für DMARC/MTA-STS, komplett ohne DB (die
CLI-Verdrahtung inklusive echter Ingest wird in test_cli_stats.py geprüft)."""
from dmarcwatch.report import (
    ReportRow,
    TLSPolicyRow,
    _recommended_observation_days,
    collect_daily_stats,
    collect_tls_daily_stats,
    compute_dmarc_readiness,
    compute_mta_sts_readiness,
    to_stats_json_dict,
)


def _row(
    date_begin: int, is_flagged: bool = False, flag_reasons=None,
    domain: str = "example.com", policy_p: str = "quarantine", policy_pct: int = 100,
) -> ReportRow:
    return ReportRow(
        date_begin=date_begin, org_name="google.com", source_ip="192.0.2.1", count=1,
        disposition="none", dkim="pass", spf="pass", envelope_to="",
        is_flagged=is_flagged, flag_reasons=flag_reasons or [],
        domain=domain, policy_p=policy_p, policy_pct=policy_pct,
    )


# 2026-08-20 00:00:00 UTC und 2026-08-21 00:00:00 UTC als feste Zeitstempel,
# damit die Tests nicht vom aktuellen Datum abhängen.
DAY1 = 1787184000
DAY2 = 1787270400


# --- collect_daily_stats() ---


def test_collect_daily_stats_groups_by_day_chronologically():
    rows = [_row(DAY2), _row(DAY1), _row(DAY1, is_flagged=True)]
    result = collect_daily_stats(rows)
    assert [d.date for d in result] == ["2026-08-20", "2026-08-21"]
    assert result[0].clean_count == 1
    assert result[0].flagged_count == 1
    assert result[1].clean_count == 1
    assert result[1].flagged_count == 0


def test_collect_daily_stats_empty_input():
    assert collect_daily_stats([]) == []


# --- collect_tls_daily_stats() ---


def _tls_row_at(date_begin: int, successful: int = 5, failures: int = 0) -> TLSPolicyRow:
    return TLSPolicyRow(
        tls_policy_id=1, date_begin=date_begin, org_name="google.com", policy_domain="example.com",
        policy_type="sts", successful_session_count=successful, failure_count=failures,
        failure_result_types=[],
    )


def test_collect_tls_daily_stats_groups_by_day_chronologically():
    rows = [_tls_row_at(DAY2, successful=3, failures=1), _tls_row_at(DAY1, successful=10, failures=0)]
    result = collect_tls_daily_stats(rows)
    assert [d.date for d in result] == ["2026-08-20", "2026-08-21"]
    assert result[0].successful_count == 10
    assert result[0].failure_count == 0
    assert result[1].successful_count == 3
    assert result[1].failure_count == 1


def test_collect_tls_daily_stats_sums_multiple_policies_same_day():
    rows = [_tls_row_at(DAY1, successful=5, failures=1), _tls_row_at(DAY1, successful=3, failures=2)]
    result = collect_tls_daily_stats(rows)
    assert len(result) == 1
    assert result[0].successful_count == 8
    assert result[0].failure_count == 3


def test_collect_tls_daily_stats_empty_input():
    assert collect_tls_daily_stats([]) == []


# --- _recommended_observation_days() ---


def test_recommended_observation_days_low_volume():
    assert _recommended_observation_days(0.5) == 60


def test_recommended_observation_days_medium_volume():
    assert _recommended_observation_days(3) == 30


def test_recommended_observation_days_high_volume():
    assert _recommended_observation_days(10) == 14


def test_recommended_observation_days_boundaries_are_inclusive_on_the_lower_tier():
    assert _recommended_observation_days(1) == 30
    assert _recommended_observation_days(5) == 14


# --- compute_dmarc_readiness() ---
#
# until_ts simuliert "jetzt" - der tatsächlich beobachtete Zeitraum ist
# das Alter des ältesten Reports bis until_ts, NICHT das bloß angefragte
# `days` (siehe compute_dmarc_readiness-Docstring: sonst würde ein
# einfaches `stats --days 90` sofort "90 Tage beobachtet" behaupten, egal
# wie lange die Domain real schon Reports liefert). In den meisten Tests
# unten steht until_ts absichtlich 90 Tage nach dem ältesten Report -
# 90 Tage übertreffen selbst den strengsten Richtwert (60 Tage bei sehr
# wenig Volumen), sodass die Mindestbeobachtungsdauer diese Tests nicht
# verdeckt, die eigentlich own_ip_auth_failures/aktuelle Policy/Domain-
# Gruppierung prüfen. Die Mindestbeobachtungsdauer selbst wird weiter
# unten gezielt mit einem kurzen Zeitraum getestet.

_DAY_SECS = 86400


def test_dmarc_readiness_ready_when_only_unknown_ip_failures():
    """Unbekannte IPs zählen nicht gegen die Bereitschaft - genau die soll
    p=reject ja blockieren."""
    rows = [
        _row(DAY1, policy_p="quarantine"),
        _row(DAY2, is_flagged=True, flag_reasons=["unknown_ip"], policy_p="quarantine"),
    ]
    result = compute_dmarc_readiness(rows, days=90, until_ts=DAY1 + 90 * _DAY_SECS)
    assert len(result) == 1
    r = result[0]
    assert r.domain == "example.com"
    assert r.current_policy == "quarantine"
    assert r.unknown_ip_failures == 1
    assert r.own_ip_auth_failures == 0
    assert r.ready_for_reject is True


def test_dmarc_readiness_not_ready_with_own_ip_auth_failure():
    """Ein Fehlschlag einer bekannten eigenen IP würde eine schärfere
    Policy zusätzlich zum eigentlichen Spoofing-Versuch blockieren."""
    rows = [
        _row(DAY1, is_flagged=True, flag_reasons=["own_ip_auth_fail"], policy_p="quarantine"),
    ]
    result = compute_dmarc_readiness(rows, days=90, until_ts=DAY1 + 90 * _DAY_SECS)
    assert result[0].own_ip_auth_failures == 1
    assert result[0].ready_for_reject is False


def test_dmarc_readiness_already_at_reject_not_marked_ready():
    rows = [_row(DAY1, policy_p="reject")]
    result = compute_dmarc_readiness(rows, days=90, until_ts=DAY1 + 90 * _DAY_SECS)
    assert result[0].current_policy == "reject"
    assert result[0].ready_for_reject is False


def test_dmarc_readiness_uses_most_recent_report_for_current_policy():
    rows = [_row(DAY1, policy_p="none"), _row(DAY2, policy_p="quarantine")]
    result = compute_dmarc_readiness(rows, days=90, until_ts=DAY1 + 90 * _DAY_SECS)
    assert result[0].current_policy == "quarantine"


def test_dmarc_readiness_groups_by_domain():
    rows = [_row(DAY1, domain="a.example"), _row(DAY1, domain="b.example")]
    result = compute_dmarc_readiness(rows, days=90, until_ts=DAY1 + 90 * _DAY_SECS)
    assert {r.domain for r in result} == {"a.example", "b.example"}


def test_dmarc_readiness_empty_without_rows():
    assert compute_dmarc_readiness([], days=30, until_ts=DAY1) == []


def test_dmarc_readiness_not_ready_when_observation_window_too_short_for_volume():
    """Intelligent statt eines starren Zeitraums: bei sehr wenig Volumen
    (hier 1 Eintrag über 7 real beobachtete Tage, also weit unter 1/Tag)
    empfiehlt _recommended_observation_days 60 Tage - 7 reichen nicht,
    obwohl keine einzige eigene IP fehlschlägt."""
    rows = [_row(DAY1, policy_p="quarantine")]
    result = compute_dmarc_readiness(rows, days=7, until_ts=DAY1 + 7 * _DAY_SECS)
    assert result[0].own_ip_auth_failures == 0
    assert result[0].recommended_observation_days == 60
    assert result[0].observed_days == 7
    assert result[0].ready_for_reject is False


def test_dmarc_readiness_not_ready_when_days_requested_exceeds_real_history():
    """Der eigentliche Bugfix: ein größeres --days-Fenster allein darf
    keine längere Beobachtungszeit vortäuschen, wenn der älteste Report
    real viel jünger ist - genau der Fall, den ein Nutzer live beobachtet
    hat (stats --days 90 zeigte weiterhin "0.9 Einträge/Tag" und wurde
    trotzdem grün, obwohl die Domain real erst seit 30 Tagen Reports
    hat)."""
    rows = [_row(DAY1, policy_p="quarantine")]
    # until_ts nur 10 Tage nach dem einzigen Report, obwohl days=90
    # angefragt wurde - die Domain hat real erst seit 10 Tagen Reports.
    result = compute_dmarc_readiness(rows, days=90, until_ts=DAY1 + 10 * _DAY_SECS)
    assert result[0].observed_days == 10
    assert result[0].ready_for_reject is False


def test_dmarc_readiness_ready_once_observation_window_matches_volume():
    rows = [_row(DAY1, policy_p="quarantine")]
    result = compute_dmarc_readiness(rows, days=60, until_ts=DAY1 + 60 * _DAY_SECS)
    assert result[0].ready_for_reject is True


# --- compute_mta_sts_readiness() ---


def _tls_row(failure_count: int) -> TLSPolicyRow:
    return TLSPolicyRow(
        tls_policy_id=1, date_begin=DAY1, org_name="google.com", policy_domain="example.com",
        policy_type="sts", successful_session_count=10, failure_count=failure_count,
        failure_result_types=[],
    )


def test_mta_sts_readiness_no_data():
    result = compute_mta_sts_readiness([], days=30, until_ts=DAY1)
    assert result.has_data is False
    assert result.ready_for_enforce is False


def test_mta_sts_readiness_ready_with_zero_failures():
    # 10 Policies x 10 erfolgreiche Sitzungen = 100 Sitzungen über 14 real
    # beobachtete Tage -> ca. 7.1/Tag, damit klar oberhalb der 5/Tag-
    # Schwelle ("hohes Volumen", 14 Tage empfohlen) - 14 Tage Beobachtung
    # reichen dann.
    result = compute_mta_sts_readiness([_tls_row(0)] * 10, days=14, until_ts=DAY1 + 14 * _DAY_SECS)
    assert result.has_data is True
    assert result.total_failure_count == 0
    assert result.ready_for_enforce is True


def test_mta_sts_readiness_not_ready_with_failures():
    result = compute_mta_sts_readiness([_tls_row(0), _tls_row(3)], days=90, until_ts=DAY1 + 90 * _DAY_SECS)
    assert result.total_failure_count == 3
    assert result.ready_for_enforce is False


def test_mta_sts_readiness_not_ready_when_observation_window_too_short_for_volume():
    # 1 Policy = 10 Sitzungen über 7 real beobachtete Tage -> ca. 1.4/Tag
    # ("mittleres Volumen", 30 Tage empfohlen) - 7 Tage reichen nicht.
    result = compute_mta_sts_readiness([_tls_row(0)], days=7, until_ts=DAY1 + 7 * _DAY_SECS)
    assert result.total_failure_count == 0
    assert result.recommended_observation_days == 30
    assert result.ready_for_enforce is False


def test_mta_sts_readiness_not_ready_when_days_requested_exceeds_real_history():
    """Gleicher Bugfix wie bei DMARC oben: --days=90 darf keine 90 Tage
    Beobachtung vortäuschen, wenn der älteste TLS-RPT-Report real erst
    10 Tage alt ist."""
    result = compute_mta_sts_readiness([_tls_row(0)], days=90, until_ts=DAY1 + 10 * _DAY_SECS)
    assert result.observed_days == 10
    assert result.ready_for_enforce is False


# --- to_stats_json_dict() ---


def test_to_stats_json_dict_structure():
    rows = [_row(DAY1)]
    tls_rows = [_tls_row_at(DAY1, successful=5, failures=1)]
    daily = collect_daily_stats(rows)
    tls_daily = collect_tls_daily_stats(tls_rows)
    until_ts = DAY1 + 30 * _DAY_SECS
    dmarc_readiness = compute_dmarc_readiness(rows, days=30, until_ts=until_ts)
    mta_sts_readiness = compute_mta_sts_readiness(tls_rows, days=30, until_ts=until_ts)

    data = to_stats_json_dict(30, daily, dmarc_readiness, mta_sts_readiness, tls_daily)

    assert data["days"] == 30
    assert data["daily"] == [{"date": "2026-08-20", "clean_count": 1, "flagged_count": 0}]
    assert data["tls_daily"] == [{"date": "2026-08-20", "successful_count": 5, "failure_count": 1}]
    assert data["dmarc_readiness"][0]["domain"] == "example.com"
    assert data["dmarc_readiness"][0]["recommended_observation_days"] == 60
    assert data["mta_sts_readiness"]["has_data"] is True


def test_to_stats_json_dict_tls_daily_defaults_to_empty():
    data = to_stats_json_dict(30, [], [], compute_mta_sts_readiness([], days=30, until_ts=DAY1))
    assert data["tls_daily"] == []
