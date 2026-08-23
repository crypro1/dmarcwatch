"""Lokaler Spamhaus-Cache (dmarcwatch inspect --blacklist -> store.py ->
Menüleiste). Mirrors test_whois_cache.py - gleiche "nie selbst nachfragen,
nur lesen"-Regel für get_all_cached_blacklist()."""
from dmarcwatch.report import ReportRow, to_json_dict
from dmarcwatch.store import (
    connect,
    get_all_cached_blacklist,
    get_cached_blacklist,
    set_cached_blacklist,
)


def test_set_and_get_cached_blacklist_roundtrip(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    assert get_cached_blacklist(conn, "198.51.100.5") is None

    set_cached_blacklist(conn, "198.51.100.5", True, ["SBL - bekannte Spam-Quelle"])
    result = get_cached_blacklist(conn, "198.51.100.5")
    assert result is not None
    listed, reasons, checked_at = result
    assert listed is True
    assert reasons == ["SBL - bekannte Spam-Quelle"]
    assert checked_at > 0


def test_set_cached_blacklist_overwrites_previous_value(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    set_cached_blacklist(conn, "198.51.100.5", True, ["SBL - bekannte Spam-Quelle"])
    set_cached_blacklist(conn, "198.51.100.5", False, [])
    listed, reasons, _ = get_cached_blacklist(conn, "198.51.100.5")
    assert listed is False
    assert reasons == []


def test_get_all_cached_blacklist_returns_everything(tmp_path):
    conn = connect(tmp_path / "dmarc.sqlite")
    set_cached_blacklist(conn, "198.51.100.5", True, ["SBL - bekannte Spam-Quelle"])
    set_cached_blacklist(conn, "192.0.2.1", False, [])
    result = get_all_cached_blacklist(conn)
    assert result == {
        "198.51.100.5": (True, ["SBL - bekannte Spam-Quelle"]),
        "192.0.2.1": (False, []),
    }


def test_to_json_dict_includes_cached_blacklist_status():
    rows = [
        ReportRow(
            date_begin=1700000000, org_name="unknown-sender.example", source_ip="198.51.100.5",
            count=1, disposition="none", dkim="pass", spf="fail", envelope_to="",
            is_flagged=True, flag_reasons=["unknown_ip"],
        ),
        ReportRow(
            date_begin=1700000000, org_name="AMAZON-SES", source_ip="192.0.2.1",
            count=1, disposition="none", dkim="pass", spf="pass", envelope_to="",
            is_flagged=False, flag_reasons=[],
        ),
    ]
    data = to_json_dict(
        rows, days=7,
        blacklist_by_ip={"198.51.100.5": (True, ["SBL - bekannte Spam-Quelle"])},
    )
    records = data["days_grouped"][0]["records"]
    by_ip = {r["source_ip"]: r for r in records}
    assert by_ip["198.51.100.5"]["blacklist_listed"] is True
    assert by_ip["198.51.100.5"]["blacklist_reasons"] == ["SBL - bekannte Spam-Quelle"]
    assert by_ip["192.0.2.1"]["blacklist_listed"] is None
    assert by_ip["192.0.2.1"]["blacklist_reasons"] == []


def test_to_json_dict_without_blacklist_cache_defaults_to_none():
    rows = [
        ReportRow(
            date_begin=1700000000, org_name="unknown-sender.example", source_ip="198.51.100.5",
            count=1, disposition="none", dkim="pass", spf="fail", envelope_to="",
            is_flagged=True, flag_reasons=["unknown_ip"],
        ),
    ]
    data = to_json_dict(rows, days=7)
    record = data["days_grouped"][0]["records"][0]
    assert record["blacklist_listed"] is None
    assert record["blacklist_reasons"] == []
