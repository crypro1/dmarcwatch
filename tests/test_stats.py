"""Reine Berechnungen für `dmarcwatch stats` (report.py) - Tagestrend und
Verschärfungs-Einschätzung für DMARC/MTA-STS, komplett ohne DB (die
CLI-Verdrahtung inklusive echter Ingest wird in test_cli_stats.py geprüft)."""
from dmarcwatch.report import (
    MIN_SAMPLE_SIZE,
    ReportRow,
    TLSPolicyRow,
    _detect_reporting_gap,
    _next_dmarc_rollout_step,
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
    count: int = 1,
) -> ReportRow:
    return ReportRow(
        date_begin=date_begin, org_name="google.com", source_ip="192.0.2.1", count=count,
        disposition="none", dkim="pass", spf="pass", envelope_to="",
        is_flagged=is_flagged, flag_reasons=flag_reasons or [],
        domain=domain, policy_p=policy_p, policy_pct=policy_pct,
    )


# 2026-08-20 00:00:00 UTC und 2026-08-21 00:00:00 UTC als feste Zeitstempel,
# damit die Tests nicht vom aktuellen Datum abhängen.
DAY1 = 1787184000
DAY2 = 1787270400
_DAY_SECS = 86400


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


def _tls_row_at(date_begin: int, successful: int = 5, failures: int = 0, domain: str = "example.com") -> TLSPolicyRow:
    return TLSPolicyRow(
        tls_policy_id=1, date_begin=date_begin, org_name="google.com", policy_domain=domain,
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


# --- _next_dmarc_rollout_step() (F: gestaffelter pct-Rollout) ---


def test_next_rollout_step_from_none():
    assert _next_dmarc_rollout_step(None, None) == ("quarantine", 25)
    assert _next_dmarc_rollout_step("none", 100) == ("quarantine", 25)


def test_next_rollout_step_ramps_pct_within_quarantine():
    assert _next_dmarc_rollout_step("quarantine", 25) == ("quarantine", 50)
    assert _next_dmarc_rollout_step("quarantine", 90) == ("quarantine", 100)


def test_next_rollout_step_moves_from_quarantine_to_reject_once_pct_100():
    assert _next_dmarc_rollout_step("quarantine", 100) == ("reject", 25)


def test_next_rollout_step_ramps_pct_within_reject():
    assert _next_dmarc_rollout_step("reject", 25) == ("reject", 50)
    assert _next_dmarc_rollout_step("reject", 90) == ("reject", 100)


def test_next_rollout_step_none_once_fully_enforced():
    """p=reject; pct=100 ist der einzige Zustand ohne weiteren Schritt -
    p=reject bei kleinerem pct ist NICHT fertig."""
    assert _next_dmarc_rollout_step("reject", 100) is None


# --- _detect_reporting_gap() (K) ---


def test_detect_reporting_gap_no_gap_with_regular_daily_reports():
    day0 = DAY1 // _DAY_SECS
    days = [day0, day0 + 1, day0 + 2, day0 + 3]
    has_gap, gap_days = _detect_reporting_gap(days)
    assert has_gap is False
    assert gap_days == 0


def test_detect_reporting_gap_flags_large_gap_relative_to_usual_spacing():
    """Regelmäßig fast täglich, dann plötzlich 40 Tage nichts, dann geht
    es weiter - typisches Muster eines zwischenzeitlich ausgefallenen
    fetch (abgelaufene IMAP-Zugangsdaten o. Ä.), nicht einfach wenig
    Sendevolumen. Median statt Mittelwert ist hier entscheidend: der
    Mittelwert der Lücken [1,1,1,40] wäre schon durch die 40 selbst so
    hoch, dass sie sich rechnerisch nicht mehr abhebt."""
    day0 = DAY1 // _DAY_SECS
    days = [day0, day0 + 1, day0 + 2, day0 + 3, day0 + 43]
    has_gap, gap_days = _detect_reporting_gap(days)
    assert has_gap is True
    assert gap_days == 40


def test_detect_reporting_gap_does_not_flag_naturally_sparse_low_volume_domain():
    """Ein Domain mit ohnehin seltenem, aber gleichmäßig verteiltem
    Sendevolumen (z. B. alle 10 Tage ein Report) soll NICHT als Lücke
    gelten - relativ zur eigenen üblichen Lücke, nicht ein fester
    Schwellenwert."""
    day0 = DAY1 // _DAY_SECS
    days = [day0, day0 + 10, day0 + 20, day0 + 30]
    has_gap, gap_days = _detect_reporting_gap(days)
    assert has_gap is False
    assert gap_days == 0


def test_detect_reporting_gap_ignores_silence_up_to_now():
    """Bewusste Design-Entscheidung: die Zeit vom letzten Report bis
    "jetzt" zählt NICHT als Lücke - eine Domain, die seit einer Weile
    einfach wenig/nichts mehr verschickt, ist kein Alarmsignal, nur eine
    Lücke MITTEN in einer sonst regelmäßigen Historie ist eindeutig genug."""
    day0 = DAY1 // _DAY_SECS
    days = [day0, day0 + 1, day0 + 2, day0 + 3]
    has_gap, gap_days = _detect_reporting_gap(days)
    assert has_gap is False
    assert gap_days == 0


def test_detect_reporting_gap_needs_at_least_three_report_days():
    assert _detect_reporting_gap([DAY1 // _DAY_SECS]) == (False, 0)
    assert _detect_reporting_gap([]) == (False, 0)


# --- compute_dmarc_readiness() ---
#
# until_ts simuliert "jetzt" - der tatsächlich beobachtete Zeitraum ist
# das Alter des ältesten Reports bis until_ts, NICHT das bloß angefragte
# `days` (siehe compute_dmarc_readiness-Docstring). In den meisten Tests
# unten steht until_ts absichtlich 90 Tage nach dem ältesten Report und
# total_count wird künstlich über MIN_SAMPLE_SIZE gehalten - 90 Tage
# übertreffen selbst den strengsten Richtwert (60 Tage bei sehr wenig
# Volumen), sodass weder die Mindestbeobachtungsdauer noch die
# Mindest-Stichprobengröße diese Tests verdecken, die eigentlich
# own_ip_auth_failures/aktuelle Policy/Domain-Gruppierung prüfen. Beide
# Gates werden weiter unten gezielt getestet.

_SAMPLE_ROWS = [_row(DAY1 - i * _DAY_SECS, count=2) for i in range(6)]  # 12 E-Mails gesamt, >= MIN_SAMPLE_SIZE


def _readiness_for(rows, days=90, until_ts=None):
    until_ts = until_ts if until_ts is not None else DAY1 + 90 * _DAY_SECS
    return compute_dmarc_readiness(rows, days=days, until_ts=until_ts)


def test_dmarc_readiness_ready_when_only_unknown_ip_failures():
    """Unbekannte IPs zählen nicht gegen die Bereitschaft - genau die soll
    p=reject ja blockieren."""
    rows = _SAMPLE_ROWS + [_row(DAY2, is_flagged=True, flag_reasons=["unknown_ip"], policy_p="quarantine")]
    result = _readiness_for(rows)
    assert len(result) == 1
    r = result[0]
    assert r.domain == "example.com"
    assert r.current_policy == "quarantine"
    assert r.unknown_ip_failures == 1
    assert r.own_ip_auth_failures == 0
    assert r.ready_for_next_step is True
    # _row()-Default ist policy_pct=100, also quarantine bereits voll
    # ausgerollt - nächster Schritt ist reject@25, nicht quarantine@25.
    assert r.next_recommended_policy == "reject"
    assert r.next_recommended_pct == 25


def test_dmarc_readiness_not_ready_with_recent_own_ip_auth_failure():
    """Ein FRISCHER Fehlschlag einer bekannten eigenen IP blockiert - würde
    eine schärfere Policy zusätzlich zum eigentlichen Problem verstecken."""
    rows = _SAMPLE_ROWS + [
        _row(DAY1 + 89 * _DAY_SECS, is_flagged=True, flag_reasons=["own_ip_auth_fail"], policy_p="quarantine"),
    ]
    result = _readiness_for(rows)
    assert result[0].own_ip_auth_failures == 1
    assert result[0].clean_days == 1  # bis until_ts=DAY1+90*_DAY_SECS
    assert result[0].ready_for_next_step is False


def test_dmarc_readiness_old_own_ip_auth_failure_heals_after_enough_clean_time():
    """A: ein ALTER Fehlschlag blockiert NICHT mehr unbegrenzt, sobald seit
    ihm genug Zeit (relativ zum Sendevolumen) vergangen ist - anders als
    die alte, starre 'keine einzige Zeile im ganzen Fenster'-Regel."""
    rows = _SAMPLE_ROWS + [
        _row(DAY1, is_flagged=True, flag_reasons=["own_ip_auth_fail"], policy_p="quarantine"),
    ]
    result = _readiness_for(rows, until_ts=DAY1 + 90 * _DAY_SECS)
    assert result[0].own_ip_auth_failures == 1
    assert result[0].last_failure_date == "2026-08-20"
    # 90 Tage seit dem einzigen (alten) Fehlschlag vergangen, avg_daily_volume
    # gering genug für 60 Tage Richtwert - 90 >= 60, also geheilt.
    assert result[0].clean_days == 90
    assert result[0].ready_for_next_step is True


def test_dmarc_readiness_already_at_reject_pct_100_is_fully_enforced():
    rows = [_row(DAY1 - i * _DAY_SECS, count=2, policy_p="reject", policy_pct=100) for i in range(6)]
    result = _readiness_for(rows)
    assert result[0].current_policy == "reject"
    assert result[0].fully_enforced is True
    assert result[0].next_recommended_policy is None
    assert result[0].ready_for_next_step is False


def test_dmarc_readiness_reject_with_partial_pct_still_recommends_next_step():
    """F: der ehemals binäre 'current_policy == reject -> fertig'-Check
    ignorierte pct komplett - p=reject; pct=10 ist NICHT fertig."""
    rows = [_row(DAY1 - i * _DAY_SECS, count=2, policy_p="reject", policy_pct=10) for i in range(6)]
    result = _readiness_for(rows)
    assert result[0].fully_enforced is False
    assert result[0].next_recommended_policy == "reject"
    assert result[0].next_recommended_pct == 35
    assert result[0].ready_for_next_step is True


def test_dmarc_readiness_needs_recheck_when_reject_domain_gets_a_recent_failure():
    """C: Regression-Warnung - eine Domain, die schon bei p=reject steht,
    aber gerade einen frischen own_ip_auth_fail bekommt, braucht einen
    expliziten Hinweis statt stillschweigend als 'erledigt' zu gelten."""
    rows = [_row(DAY1 - i * _DAY_SECS, count=2, policy_p="reject", policy_pct=100) for i in range(6)]
    rows.append(
        _row(DAY1 + 89 * _DAY_SECS, is_flagged=True, flag_reasons=["own_ip_auth_fail"], policy_p="reject", policy_pct=100)
    )
    result = _readiness_for(rows, until_ts=DAY1 + 90 * _DAY_SECS)
    assert result[0].current_policy == "reject"
    assert result[0].fully_enforced is True
    assert result[0].needs_recheck is True


def test_dmarc_readiness_no_recheck_when_reject_domain_stays_clean():
    rows = [_row(DAY1 - i * _DAY_SECS, count=2, policy_p="reject", policy_pct=100) for i in range(6)]
    result = _readiness_for(rows)
    assert result[0].needs_recheck is False


def test_dmarc_readiness_uses_most_recent_report_for_current_policy():
    rows = _SAMPLE_ROWS + [_row(DAY1, policy_p="none"), _row(DAY2, policy_p="quarantine")]
    result = _readiness_for(rows)
    assert result[0].current_policy == "quarantine"


def test_dmarc_readiness_groups_by_domain():
    rows = [_row(DAY1, domain="a.example"), _row(DAY1, domain="b.example")]
    result = _readiness_for(rows)
    assert {r.domain for r in result} == {"a.example", "b.example"}


def test_dmarc_readiness_empty_without_rows():
    assert compute_dmarc_readiness([], days=30, until_ts=DAY1) == []


def test_dmarc_readiness_counts_real_messages_not_report_rows():
    """B: total_count/unknown_ip_failures/own_ip_auth_failures zählen
    echte Nachrichten (ReportRow.count), nicht die Anzahl der
    Report-Zeilen - eine Zeile kann hunderte Nachrichten einer IP
    zusammenfassen."""
    rows = [
        _row(DAY1, count=500),
        _row(DAY2, count=1, is_flagged=True, flag_reasons=["unknown_ip"]),
    ]
    result = _readiness_for(rows)
    assert result[0].total_count == 501
    assert result[0].unknown_ip_failures == 1


def test_dmarc_readiness_not_ready_when_observation_window_too_short_for_volume():
    """Intelligent statt eines starren Zeitraums: bei sehr wenig Volumen
    (hier 1 E-Mail über 7 real beobachtete Tage, also weit unter 1/Tag)
    empfiehlt _recommended_observation_days 60 Tage - 7 reichen nicht,
    obwohl keine einzige eigene IP fehlschlägt (die Stichprobengröße
    unten ist bewusst nicht der Grund für "nicht bereit" - die wird
    separat getestet)."""
    rows = [_row(DAY1, policy_p="quarantine")]
    result = _readiness_for(rows, days=7, until_ts=DAY1 + 7 * _DAY_SECS)
    assert result[0].own_ip_auth_failures == 0
    assert result[0].recommended_observation_days == 60
    assert result[0].observed_days == 7
    assert result[0].clean_days == 7
    assert result[0].ready_for_next_step is False


def test_dmarc_readiness_not_ready_when_days_requested_exceeds_real_history():
    """Der --days-Bugfix bleibt gültig unter der neuen Logik: ein größeres
    --days-Fenster allein darf keine längere Beobachtungszeit vortäuschen,
    wenn der älteste Report real viel jünger ist. _SAMPLE_ROWS' ältester
    Report liegt 5 Tage vor DAY1, until_ts hier 10 Tage nach DAY1 - also
    15 real beobachtete Tage, nicht die vollen 90 aus --days."""
    rows = _SAMPLE_ROWS
    result = _readiness_for(rows, days=90, until_ts=DAY1 + 10 * _DAY_SECS)
    assert result[0].observed_days == 15
    assert result[0].clean_days == 15
    assert result[0].ready_for_next_step is False


def test_dmarc_readiness_ready_once_observation_window_matches_volume():
    rows = _SAMPLE_ROWS
    result = _readiness_for(rows, days=90, until_ts=DAY1 + 90 * _DAY_SECS)
    assert result[0].ready_for_next_step is True


def test_dmarc_readiness_not_ready_below_minimum_sample_size():
    """D: eine Mindest-Stichprobengröße unabhängig vom Zeitfenster - 60
    Tage seit dem letzten (nicht vorhandenen) Fehlschlag reichen nicht,
    wenn insgesamt nur 2 echte E-Mails beobachtet wurden."""
    rows = [_row(DAY1, count=2)]
    result = _readiness_for(rows, days=90, until_ts=DAY1 + 90 * _DAY_SECS)
    assert result[0].total_count == 2
    assert result[0].total_count < MIN_SAMPLE_SIZE
    assert result[0].clean_days >= result[0].recommended_observation_days
    assert result[0].ready_for_next_step is False


def test_dmarc_readiness_ready_once_minimum_sample_size_reached():
    rows = [_row(DAY1, count=MIN_SAMPLE_SIZE)]
    result = _readiness_for(rows, days=90, until_ts=DAY1 + 90 * _DAY_SECS)
    assert result[0].total_count == MIN_SAMPLE_SIZE
    assert result[0].ready_for_next_step is True


def test_dmarc_readiness_reporting_gap_blocks_readiness():
    """K: eine auffällige Report-Lücke blockiert die Bereitschaft, auch
    wenn Volumen/Zeit/Fehlschläge für sich genommen "bereit" ergeben
    würden - eine Lücke könnte ein ausgefallener fetch sein, keine
    bestätigt saubere Zeit."""
    day0 = DAY1 // _DAY_SECS
    rows = [
        _row(day0 * _DAY_SECS, count=3),
        _row((day0 + 1) * _DAY_SECS, count=3),
        _row((day0 + 2) * _DAY_SECS, count=3),
        _row((day0 + 3) * _DAY_SECS, count=3),
        _row((day0 + 90) * _DAY_SECS, count=3),
    ]
    result = _readiness_for(rows, days=90, until_ts=(day0 + 90) * _DAY_SECS)
    assert result[0].has_reporting_gap is True
    assert result[0].ready_for_next_step is False


def test_dmarc_readiness_recent_volume_window_not_diluted_by_older_quiet_period():
    """J: avg_daily_volume soll das AKTUELLE Sendevolumen widerspiegeln,
    nicht durch eine viel ältere, ruhigere Phase verwässert werden - eine
    Domain, die vor 200 Tagen kaum etwas verschickt hat und seit 25 Tagen
    durchgehend hochvolumig sendet, braucht den kurzen (14-Tage-)Richtwert,
    nicht den durch die alte Ruhephase aufgeblähten 60-Tage-Richtwert."""
    until_ts = DAY1 + 200 * _DAY_SECS
    old_quiet_row = _row(DAY1, count=1)
    # Genau 30 Tage durchgehend hochvolumig, damit das jüngere
    # 30-Tage-Fenster (_RECENT_VOLUME_WINDOW_DAYS) vollständig damit gefüllt
    # ist - sonst würden die nicht abgedeckten Resttage im Fenster den
    # Schnitt wieder verwässern.
    recent_high_volume_rows = [
        _row(until_ts - i * _DAY_SECS, count=10) for i in range(30)
    ]
    rows = [old_quiet_row] + recent_high_volume_rows
    result = _readiness_for(rows, days=200, until_ts=until_ts)
    # 30 Tage x 10 E-Mails / 30 Tage (jüngeres Fenster) = 10/Tag -> hohes
    # Volumen, 14 Tage empfohlen statt der durch die alte Ruhephase
    # aufgeblähten 60 Tage.
    assert result[0].avg_daily_volume == 10.0
    assert result[0].recommended_observation_days == 14


# --- compute_mta_sts_readiness() ---


def _tls_row(failure_count: int, date_begin: int = DAY1, domain: str = "example.com", failure_type_counts=None) -> TLSPolicyRow:
    return TLSPolicyRow(
        tls_policy_id=1, date_begin=date_begin, org_name="google.com", policy_domain=domain,
        policy_type="sts", successful_session_count=10, failure_count=failure_count,
        failure_result_types=[], failure_type_counts=failure_type_counts or {},
    )


def test_mta_sts_readiness_no_data():
    result = compute_mta_sts_readiness([], days=30, until_ts=DAY1)
    assert result == []


def test_mta_sts_readiness_ready_with_zero_failures():
    # 10 Policies x 10 erfolgreiche Sitzungen = 100 Sitzungen über 14 real
    # beobachtete Tage -> ca. 7.1/Tag, damit klar oberhalb der 5/Tag-
    # Schwelle ("hohes Volumen", 14 Tage empfohlen) - 14 Tage Beobachtung
    # reichen dann.
    result = compute_mta_sts_readiness([_tls_row(0)] * 10, days=14, until_ts=DAY1 + 14 * _DAY_SECS)
    assert len(result) == 1
    assert result[0].total_failure_count == 0
    assert result[0].ready_for_enforce is True


def test_mta_sts_readiness_not_ready_with_recent_failure():
    result = compute_mta_sts_readiness(
        [_tls_row(0, date_begin=DAY1)] * 9 + [_tls_row(3, date_begin=DAY1 + 89 * _DAY_SECS)],
        days=90, until_ts=DAY1 + 90 * _DAY_SECS,
    )
    assert result[0].total_failure_count == 3
    assert result[0].clean_days == 1
    assert result[0].ready_for_enforce is False


def test_mta_sts_readiness_old_failure_heals_after_enough_clean_time():
    """A für MTA-STS: ein alter TLS-Fehlschlag blockiert nicht mehr, sobald
    seitdem genug Zeit vergangen ist."""
    result = compute_mta_sts_readiness(
        [_tls_row(3, date_begin=DAY1)] + [_tls_row(0, date_begin=DAY1)] * 9,
        days=90, until_ts=DAY1 + 90 * _DAY_SECS,
    )
    assert result[0].total_failure_count == 3
    assert result[0].clean_days == 90
    assert result[0].ready_for_enforce is True


def test_mta_sts_readiness_not_ready_when_observation_window_too_short_for_volume():
    # 1 Policy = 10 Sitzungen über 7 real beobachtete Tage -> ca. 1.4/Tag
    # ("mittleres Volumen", 30 Tage empfohlen) - 7 Tage reichen nicht.
    result = compute_mta_sts_readiness([_tls_row(0)], days=7, until_ts=DAY1 + 7 * _DAY_SECS)
    assert result[0].total_failure_count == 0
    assert result[0].recommended_observation_days == 30
    assert result[0].ready_for_enforce is False


def test_mta_sts_readiness_not_ready_when_days_requested_exceeds_real_history():
    result = compute_mta_sts_readiness([_tls_row(0)] * 10, days=90, until_ts=DAY1 + 10 * _DAY_SECS)
    assert result[0].observed_days == 10
    assert result[0].ready_for_enforce is False


def test_mta_sts_readiness_not_ready_below_minimum_sample_size():
    """D für MTA-STS: 90 Tage seit dem letzten (nicht vorhandenen)
    Fehlschlag reichen nicht, wenn insgesamt nur 5 echte Sitzungen
    beobachtet wurden."""
    result = compute_mta_sts_readiness(
        [TLSPolicyRow(tls_policy_id=1, date_begin=DAY1, org_name="google.com", policy_domain="example.com",
                      policy_type="sts", successful_session_count=5, failure_count=0, failure_result_types=[])],
        days=90, until_ts=DAY1 + 90 * _DAY_SECS,
    )
    assert result[0].total_sessions == 5
    assert result[0].total_sessions < MIN_SAMPLE_SIZE
    assert result[0].ready_for_enforce is False


def test_mta_sts_readiness_groups_by_domain():
    """Bugfix: MTA-STS-Bereitschaft war früher über ALLE Domains hinweg zu
    einer einzigen Einschätzung zusammengefasst statt wie bei DMARC pro
    Domain - eine zweite, unabhängige Domain hätte die Einschätzung der
    ersten verwässert. b.example bekommt einen FRISCHEN Fehlschlag (nicht
    nur irgendeinen im Fenster), damit der Test auch unter der neuen,
    zeitbasierten Logik eindeutig "noch nicht bereit" bleibt."""
    result = compute_mta_sts_readiness(
        [_tls_row(0, domain="a.example")] * 10
        + [_tls_row(0, date_begin=DAY1, domain="b.example")] * 9
        + [_tls_row(5, date_begin=DAY1 + 89 * _DAY_SECS, domain="b.example")],
        days=90, until_ts=DAY1 + 90 * _DAY_SECS,
    )
    by_domain = {r.domain: r for r in result}
    assert set(by_domain) == {"a.example", "b.example"}
    assert by_domain["a.example"].total_failure_count == 0
    assert by_domain["a.example"].ready_for_enforce is True
    assert by_domain["b.example"].total_failure_count == 5
    assert by_domain["b.example"].clean_days == 1
    assert by_domain["b.example"].ready_for_enforce is False


def test_mta_sts_readiness_failure_types_weighted_by_failed_session_count():
    """G: Fehlertypen werden mit echten fehlgeschlagenen Sitzungen
    gewichtet, nicht nur als Anzahl von failure-details-Einträgen
    gezählt - ein Eintrag kann hunderte Sitzungen abdecken."""
    rows = [
        _tls_row(3, failure_type_counts={"certificate-expired": 3}),
        _tls_row(500, failure_type_counts={"certificate-expired": 400, "sts-policy-fetch-error": 100}),
    ]
    result = compute_mta_sts_readiness(rows, days=90, until_ts=DAY1 + 90 * _DAY_SECS)
    assert result[0].failure_types == {"certificate-expired": 403, "sts-policy-fetch-error": 100}


# --- to_stats_json_dict() ---


def test_to_stats_json_dict_structure():
    rows = [_row(DAY1, count=MIN_SAMPLE_SIZE)]
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
    assert data["dmarc_readiness"][0]["next_recommended_policy"] == "reject"
    assert data["mta_sts_readiness"][0]["domain"] == "example.com"
    assert data["mta_sts_readiness"][0]["total_sessions"] == 6


def test_to_stats_json_dict_tls_daily_defaults_to_empty():
    data = to_stats_json_dict(30, [], [], compute_mta_sts_readiness([], days=30, until_ts=DAY1))
    assert data["tls_daily"] == []
    assert data["mta_sts_readiness"] == []
