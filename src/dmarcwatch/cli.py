"""CLI-Einstiegspunkt: dmarcwatch setup|fetch|report|menubar."""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
from datetime import date

from . import keychain, launchd, notify
from .anomaly import REASON_LABELS_DE
from .config import (
    Config,
    config_path,
    db_path,
    load_config,
    log_path,
    read_dns_check_result,
    read_last_fetch_date,
    read_raw_config,
    read_skipped_items,
    write_config,
    write_default_config_if_missing,
    write_dns_check_result,
    write_last_fetch_date,
    write_skipped_items,
)
from .dns_verify import _DNSSEC_VALIDATING_RESOLVER, DomainVerification, has_warnings, verify_domain
from .fetch import FetchError, connect_imap, fetch_and_ingest
from .logging_setup import setup_logging
from .report import (
    collect_daily_stats,
    collect_rows,
    collect_tls_daily_stats,
    collect_tls_rows,
    compute_dmarc_readiness,
    compute_mta_sts_readiness,
    day_range_to_ts,
    format_table,
    format_tls_table,
    has_findings,
    has_tls_failures,
    to_json_dict,
    to_stats_json_dict,
    to_tls_json_dict,
)
from .blacklist import BlacklistCheckError, check_ip_blacklist
from .menubar import render_swiftbar
from .sanitize import sanitize_field
from .spf import SPFResolutionError, resolve_own_ip_networks
from .store import (
    connect,
    get_all_cached_blacklist,
    get_all_cached_whois,
    query_records,
    set_cached_blacklist,
    set_cached_whois,
)
from .whois import WhoisLookupError, lookup_ip_organization

def _prompt(question: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{question}{suffix}: ").strip()
    return raw or default


def _prompt_required(question: str, default: str = "") -> str:
    while True:
        value = _prompt(question, default)
        if value:
            return value
        print("Bitte einen Wert eingeben.")


def _prompt_config_interactively(existing: dict) -> dict:
    print()
    print("Konfiguration einrichten (Enter übernimmt den Vorschlag in eckigen Klammern):")
    imap_host = _prompt_required("IMAP-Server", existing.get("imap_host", ""))
    imap_port_raw = _prompt("IMAP-Port", str(existing.get("imap_port", 993)))
    try:
        imap_port = int(imap_port_raw)
    except ValueError:
        print(f"Ungültiger Port {imap_port_raw!r}, verwende 993.")
        imap_port = 993
    imap_user = _prompt_required(
        "IMAP-Login (echtes Postfach, NICHT die rua-Alias-Adresse aus dem DMARC-DNS-Eintrag)",
        existing.get("imap_user", ""),
    )
    imap_folder = _prompt_required(
        "IMAP-Ordner mit den Reports", existing.get("imap_folder", "INBOX/DMARC")
    )
    domains_default = ",".join(existing.get("own_domains") or [])
    domains_raw = _prompt_required("Eigene Domain(s), kommagetrennt", domains_default)
    own_domains = [d.strip() for d in domains_raw.split(",") if d.strip()]

    updated = dict(existing)
    updated.update(
        {
            "imap_host": imap_host,
            "imap_port": imap_port,
            "imap_user": imap_user,
            "imap_folder": imap_folder,
            "own_domains": own_domains,
        }
    )

    if not existing.get("own_ip_networks"):
        print()
        print(
            "Hinweis: own_ip_networks ist noch leer. Bis das gefüllt ist, gilt jede "
            "Sende-IP als unbekannt und wird markiert - kein Fehler, aber wenig "
            "aussagekräftig. Die eigenen Sende-Netze findest du in den ersten echten, "
            "sauberen Reports (source_ip) oder im eigenen SPF-DNS-Eintrag. Danach von "
            f"Hand eintragen in: {config_path()}"
        )
    if not existing.get("enable_tls_rpt"):
        print()
        print(
            "Hinweis: TLS-RPT-Auswertung (RFC 8460) ist optional und standardmäßig "
            "aus. Dafür zuerst einen eigenen Postfachordner (Default: INBOX/TLS-RPT) "
            "mit Filterregel für die TLS-RPT-rua-Adresse anlegen, dann in "
            f"{config_path()} \"enable_tls_rpt\": true setzen."
        )
    return updated


def _prompt_schedule(default_hour: int = 7, default_minute: int = 30) -> tuple[int, int]:
    raw = _prompt("Uhrzeit für den täglichen Abruf (HH:MM)", f"{default_hour:02d}:{default_minute:02d}")
    try:
        hour_str, minute_str = raw.split(":", 1)
        hour, minute = int(hour_str), int(minute_str)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError
        return hour, minute
    except ValueError:
        print(f"Ungültiges Format {raw!r}, verwende {default_hour:02d}:{default_minute:02d}.")
        return default_hour, default_minute


def cmd_setup(args: argparse.Namespace) -> int:
    if args.remove_agent or args.remove_menubar_agent:
        if args.remove_agent:
            removed = launchd.uninstall()
            print("LaunchAgent (fetch) entfernt." if removed else "Kein fetch-LaunchAgent installiert.")
        if args.remove_menubar_agent:
            # Nur noch für die Migration von der alten, plist-basierten
            # Installation: die Menüleisten-App registriert sich seit der
            # SMAppService-Umstellung selbst (siehe LoginItemManager.swift),
            # es gibt keinen --install-menubar-agent mehr, der das anlegt.
            removed = launchd.uninstall_menubar()
            print("LaunchAgent (Menüleiste) entfernt." if removed else "Kein Menüleisten-LaunchAgent installiert.")
        return 0

    config_file = config_path()
    is_first_run = not config_file.exists()
    write_default_config_if_missing(config_file)  # stellt Datei + 0600-Rechte sicher
    raw_config = read_raw_config(config_file)

    password_from_gui: str | None = None
    if args.from_stdin_json:
        # Nicht-interaktiver Pfad für die native Setup-GUI (Swift-App):
        # ein JSON-Objekt komplett über stdin, nie als Kommandozeilen-
        # argument (Prozesslisten sind für andere lokale Nutzer sichtbar) -
        # dieselbe Begründung wie beim interaktiven Passwort-Prompt in
        # keychain.py. Enthält optional "password", das nie in raw_config
        # landet und damit nie in config.json geschrieben wird.
        try:
            payload = json.loads(sys.stdin.read())
        except json.JSONDecodeError as exc:
            print(f"Fehler: ungültiges JSON auf stdin: {exc}", file=sys.stderr)
            return 1
        if not isinstance(payload, dict):
            print("Fehler: JSON auf stdin muss ein Objekt sein", file=sys.stderr)
            return 1
        password_from_gui = payload.pop("password", None)
        raw_config.update(payload)
        write_config(raw_config, config_file)
        print(f"Konfiguration gespeichert: {config_file}")
    elif is_first_run or args.reconfigure:
        raw_config = _prompt_config_interactively(raw_config)
        write_config(raw_config, config_file)
        print(f"Konfiguration gespeichert: {config_file}")
    else:
        print(f"Konfiguration: {config_file} (bereits vorhanden, mit --reconfigure änderbar)")

    try:
        config = Config.from_dict(raw_config)
    except ValueError as exc:
        print(f"Fehler in der Konfiguration: {exc}", file=sys.stderr)
        return 1

    if args.from_stdin_json:
        if password_from_gui:
            try:
                keychain.set_password(config.imap_user, password_from_gui)
            except keychain.KeychainError as exc:
                print(f"Fehler: {exc}", file=sys.stderr)
                return 1
            print(f"Passwort im Schlüsselbund gespeichert (Account={config.imap_user!r}).")
    else:
        existing_password = keychain.get_password(config.imap_user)
        if existing_password and not args.reset_password:
            print(f"Passwort für {config.imap_user!r} bereits im Schlüsselbund, überspringe Eingabe.")
            print("(Mit --reset-password erneut eingeben, z. B. nach einem Passwortwechsel.)")
        else:
            print(
                "Schlüsselbund-Eintrag anlegen. Bitte ein anwendungsspezifisches "
                "Passwort von mailbox.org verwenden, nicht das Hauptpasswort."
            )
            try:
                keychain.prompt_and_store(config.imap_user)
            except keychain.KeychainError as exc:
                print(f"Fehler: {exc}", file=sys.stderr)
                return 1

    if args.install_agent:
        if args.hour is not None and args.minute is not None:
            hour, minute = args.hour, args.minute
        else:
            hour, minute = _prompt_schedule()
        target = launchd.install(hour=hour, minute=minute)
        print(f"LaunchAgent (fetch) installiert: {target}")
        print(f"Läuft künftig täglich um {hour:02d}:{minute:02d} Uhr.")

    print(f"Konfiguration bei Bedarf anpassen: {config_file}")
    print("Fertig. Test-Abruf mit: dmarcwatch fetch")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    config = load_config()
    logger = setup_logging(log_path(), verbose=args.verbose)

    today = time.strftime("%Y-%m-%d")
    if args.skip_if_already_run_today and read_last_fetch_date() == today:
        # Nur für den LaunchAgent gedacht (RunAtLoad, siehe launchd.py):
        # macht einen zusätzlichen Lauf bei jedem Login/Neustart sicher,
        # ohne an einem Tag, an dem der Zeitplan schon lief, unnötig
        # nochmal IMAP zu prüfen. "Jetzt abrufen" im Menü und ein von Hand
        # getipptes `dmarcwatch fetch` ignorieren das bewusst - explizite
        # Anfragen sollen immer tatsächlich nachsehen.
        if args.verbose:
            print(f"Heute ({today}) bereits erfolgreich abgerufen, überspringe.")
        return 0

    password = keychain.get_password(config.imap_user)
    if not password:
        print(
            f"Kein Passwort im Schlüsselbund für {config.imap_user!r}. "
            "Bitte zuerst 'dmarcwatch setup' ausführen.",
            file=sys.stderr,
        )
        return 2

    try:
        imap_conn = connect_imap(config, password)
    except FetchError as exc:
        logger.error("%s", exc)
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1

    db_conn = connect(db_path())
    try:
        summary = fetch_and_ingest(config, imap_conn, db_conn, logger)
    except FetchError as exc:
        logger.error("%s", exc)
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            imap_conn.logout()
        except Exception:  # noqa: BLE001 - Logout-Fehler sind nicht kritisch
            pass
        db_conn.close()

    # Nur das Datum, keine Uhrzeit oder sonstige Details - eine Zeile, die
    # bei jedem Lauf überschrieben wird, kein anwachsendes Protokoll
    # darüber, wann der Mac an/aus war.
    write_last_fetch_date(today)

    # Gründe für übersprungene Nachrichten/Anhänge (z. B. eine abgelehnte
    # Dekompressionsbombe oder ein zu großer Anhang) landen bisher nur im
    # Logfile - für die Menüleisten-App und die Terminal-Ausgabe hier
    # zusätzlich sichtbar machen. sanitize_field() schützt davor, dass ein
    # böswillig gewählter Dateiname (kommt unverändert aus einem
    # E-Mail-Anhang, also unvertrauenswürdig) in einer Menüzeile oder
    # Notification landet. Wird bei jedem Lauf komplett überschrieben, kein
    # anwachsendes Protokoll (siehe write_skipped_items).
    skipped_reasons = [sanitize_field(e, max_len=200) for e in summary.errors]
    write_skipped_items(skipped_reasons)

    logger.info(
        "Lauf beendet: %d Nachricht(en), %d zu groß/unbestimmbar, %d Report(s) neu, "
        "%d Duplikat(e), %d fremde Domain, %d auffällig, %d Anhänge übersprungen",
        summary.messages_seen,
        summary.messages_skipped_too_large,
        summary.reports_inserted,
        summary.reports_duplicate,
        summary.reports_rejected_foreign,
        summary.flagged_count,
        summary.attachments_skipped,
    )
    print(
        f"{summary.messages_seen} Nachricht(en), {summary.reports_inserted} neue Report(s), "
        f"{summary.reports_duplicate} Duplikat(e), {summary.reports_rejected_foreign} fremde Domain, "
        f"{summary.flagged_count} auffällig, {summary.attachments_skipped} Anhänge übersprungen, "
        f"{summary.messages_skipped_too_large} Nachricht(en) zu groß/unbestimmbar"
    )
    if config.enable_tls_rpt:
        print(
            f"TLS-RPT: {summary.tls_messages_seen} Nachricht(en), {summary.tls_reports_inserted} neue "
            f"Report(s), {summary.tls_reports_duplicate} Duplikat(e), "
            f"{summary.tls_reports_rejected_foreign} fremde Domain, {summary.tls_failure_count} "
            f"gemeldete Fehlschläge"
        )
    if skipped_reasons:
        print("Übersprungen:")
        for reason in skipped_reasons:
            print(f"  - {reason}")

    if config.notify_on_new_findings and summary.flagged_count > 0:
        notify.send_notification(
            title="DMARC Auffälligkeit",
            message=f"{summary.flagged_count} auffällige Einträge in neuen Reports",
        )
    if config.notify_on_new_findings and summary.tls_failure_count > 0:
        notify.send_notification(
            title="TLS-RPT Fehlschläge",
            message=f"{summary.tls_failure_count} gemeldete Fehlschläge in neuen TLS-RPT-Reports",
        )
    if config.notify_on_new_findings and skipped_reasons:
        # Rein informativ (kein "Fund" wie oben) - trotzdem sichtbar machen,
        # sonst merkt man von einem abgelehnten Angriffsversuch nie etwas,
        # außer man liest von Hand die Logdatei.
        detail = skipped_reasons[0] if len(skipped_reasons) == 1 else "Details im Menü/Terminal"
        notify.send_notification(
            title="Nachricht/Anhang übersprungen",
            message=f"{len(skipped_reasons)}x übersprungen: {detail}",
        )

    # Periodischer automatischer DNS-Check: nur wenn per Checkbox
    # ausdrücklich zugestimmt (enable_auto_dns_check) - das Aktivieren ist
    # die einmalige Zustimmung, analog zum täglichen fetch-Zeitplan selbst,
    # danach keine erneute Bestätigung pro Lauf wie bei "DNS prüfen…" im
    # Menü. Läuft huckepack im ohnehin schon täglichen fetch, kein
    # zweiter LaunchAgent nötig. Beeinflusst bewusst NICHT den Exit-Code
    # von fetch - das ist ein eigenes Signal (Konfigurationszustand), kein
    # "neuer Fund in einem Report".
    if config.enable_auto_dns_check and config.own_domains:
        last_check = read_dns_check_result()
        days_since: float | None = None
        if last_check and isinstance(last_check.get("checked_at"), str):
            try:
                last_date = date.fromisoformat(last_check["checked_at"])
                days_since = (date.today() - last_date).days
            except ValueError:
                days_since = None
        due = last_check is None or days_since is None or days_since >= config.auto_dns_check_interval_days
        if due:
            dns_results = _run_dns_check_and_persist(list(config.own_domains))
            warned_domains = [r.domain for r in dns_results if has_warnings(r)]
            if config.notify_on_new_findings and warned_domains:
                notify.send_notification(
                    title="DNS-Konfiguration auffällig",
                    message=f"Auffälligkeiten bei: {', '.join(warned_domains)}",
                )

    return 1 if (summary.flagged_count > 0 or summary.tls_failure_count > 0) else 0


def cmd_report(args: argparse.Namespace) -> int:
    db_conn = connect(db_path())
    since_ts, until_ts = day_range_to_ts(args.days)
    rows = collect_rows(db_conn, since_ts, until_ts)
    db_conn.close()
    print(format_table(rows))
    return 1 if has_findings(rows) else 0


def cmd_tls_report(args: argparse.Namespace) -> int:
    db_conn = connect(db_path())
    since_ts, until_ts = day_range_to_ts(args.days)
    rows = collect_tls_rows(db_conn, since_ts, until_ts)
    db_conn.close()
    if args.json:
        json.dump(to_tls_json_dict(rows, args.days), sys.stdout)
        sys.stdout.write("\n")
    else:
        print(format_tls_table(rows))
    return 1 if has_tls_failures(rows) else 0


def cmd_stats(args: argparse.Namespace) -> int:
    """Kompakter Überblick über den Beobachtungszeitraum - Tagestrend
    (sauber/auffällig) sowie eine Einschätzung, ob eine Verschärfung von
    DMARC (Richtung reject) bzw. MTA-STS (Richtung enforce) im Zeitraum
    sicher gewesen wäre. Reiner lokaler Lesebefehl wie `report`/
    `tls-report`, keine Live-DNS-/HTTPS-Abfrage - siehe
    compute_dmarc_readiness/compute_mta_sts_readiness in report.py."""
    db_conn = connect(db_path())
    since_ts, until_ts = day_range_to_ts(args.days)
    rows = collect_rows(db_conn, since_ts, until_ts)
    tls_rows = collect_tls_rows(db_conn, since_ts, until_ts)
    db_conn.close()

    daily = collect_daily_stats(rows)
    tls_daily = collect_tls_daily_stats(tls_rows)
    dmarc_readiness = compute_dmarc_readiness(rows, args.days, until_ts)
    mta_sts_readiness = compute_mta_sts_readiness(tls_rows, args.days, until_ts)

    if args.json:
        json.dump(
            to_stats_json_dict(args.days, daily, dmarc_readiness, mta_sts_readiness, tls_daily), sys.stdout
        )
        sys.stdout.write("\n")
        return 0

    print(f"Statistik - letzte {args.days} Tage")
    print()
    print("Tag         Sauber  Auffällig")
    for day in daily:
        print(f"{day.date}  {day.clean_count:>6}  {day.flagged_count:>9}")
    print()
    if not dmarc_readiness:
        print("DMARC: keine Reports im Zeitraum, keine Einschätzung möglich.")
    for r in dmarc_readiness:
        print(f"DMARC ({r.domain}): aktuelle Policy p={r.current_policy or '?'}, pct={r.current_pct}")
        print(f"  {r.total_count} Einträge, davon {r.unknown_ip_failures} von unbekannten IPs")
        if r.own_ip_auth_failures:
            print(f"  ⚠ {r.own_ip_auth_failures} Fehlschläge von bekannten eigenen IPs - noch nicht bereit für p=reject")
        elif r.current_policy == "reject":
            print("  Bereits bei p=reject.")
        elif r.observed_days < r.recommended_observation_days:
            print(
                f"  Noch nicht bereit: bei {r.avg_daily_volume:.1f} Einträgen/Tag werden mindestens "
                f"{r.recommended_observation_days} Tage Beobachtung empfohlen, bisher nur "
                f"{r.observed_days} Tage betrachtet."
            )
        else:
            print("  Bereit für p=reject (keine eigenen IPs mit Fehlschlägen, ausreichend Beobachtungszeit).")
    print()
    if not mta_sts_readiness.has_data:
        print("MTA-STS: keine TLS-RPT-Reports im Zeitraum, keine Einschätzung möglich.")
    elif mta_sts_readiness.total_failure_count:
        print(f"MTA-STS: {mta_sts_readiness.total_failure_count} TLS-Fehlschläge im Zeitraum - noch nicht bereit für mode=enforce.")
    elif mta_sts_readiness.observed_days < mta_sts_readiness.recommended_observation_days:
        print(
            f"MTA-STS: noch nicht bereit - bei {mta_sts_readiness.avg_daily_volume:.1f} TLS-Sitzungen/Tag "
            f"werden mindestens {mta_sts_readiness.recommended_observation_days} Tage Beobachtung empfohlen, "
            f"bisher nur {mta_sts_readiness.observed_days} Tage betrachtet."
        )
    else:
        print("MTA-STS: 0 TLS-Fehlschläge, ausreichend Beobachtungszeit - bereit für mode=enforce, falls noch nicht aktiv.")
    return 0


def _parse_inspect_query(
    query: str,
) -> tuple[str | None, ipaddress.IPv4Network | ipaddress.IPv6Network | None]:
    """Gibt (exakte_ip, netzwerk) zurück, genau eines davon ist gesetzt."""
    if "/" in query:
        return None, ipaddress.ip_network(query, strict=False)
    return str(ipaddress.ip_address(query)), None


def cmd_inspect(args: argparse.Namespace) -> int:
    """Vollständige Detailansicht für eine IP oder ein CIDR-Netz, direkt auf
    der Kommandozeile - keine Notwendigkeit, von Hand SQL gegen die
    Datenbank zu schreiben, um einem Treffer aus der Menüleiste
    nachzugehen."""
    try:
        single_ip, network = _parse_inspect_query(args.query)
    except ValueError:
        print(
            f"Fehler: {args.query!r} ist weder eine gültige IP-Adresse noch ein gültiges CIDR-Netz "
            "(z. B. 2a01:111:f403:c200::5 oder 2a01:111::/32).",
            file=sys.stderr,
        )
        return 2

    db_conn = connect(db_path())
    since_ts, until_ts = day_range_to_ts(args.days)
    rows = query_records(db_conn, since_ts, until_ts)

    matches = []
    for r in rows:
        try:
            ip = ipaddress.ip_address(r["source_ip"])
        except ValueError:
            continue
        if network is not None:
            if ip in network:
                matches.append(r)
        elif str(ip) == single_ip:
            matches.append(r)

    if not matches:
        db_conn.close()
        print(f"Keine Treffer für {args.query!r} in den letzten {args.days} Tagen.")
        return 1

    # Pro eindeutiger IP nur einmal nachschlagen, auch wenn mehrere
    # Treffer dieselbe IP haben (mehrere Reports/Tage).
    whois_cache: dict[str, str] = {}
    blacklist_cache: dict[str, str] = {}
    # Signalisiert der Menüleisten-App per Exit-Code (siehe return unten),
    # dass mindestens eine --whois/--blacklist-Abfrage fehlgeschlagen ist -
    # unabhängig vom bewusst weiter fehlenden Caching dieser Fehlschläge
    # (siehe Kommentare an den except-Zweigen unten). Ohne dieses Signal
    # bliebe der Exit-Code bei einem Fehlschlag 0 (wie ein voller Erfolg),
    # die Menüleisten-App müsste sonst deutschen Ausgabetext nach
    # "Abfrage fehlgeschlagen" durchsuchen, um das zu erkennen.
    inline_lookup_failed = False

    for r in matches:
        reasons = [x for x in (r["flag_reasons"] or "").split(",") if x]
        print("=" * 60)
        print(f"Datum:            {time.strftime('%Y-%m-%d', time.gmtime(r['date_begin']))}")
        print(f"Melder:           {sanitize_field(r['org_name'], 80)}")
        print(f"Report-ID:        {sanitize_field(r['report_id'], 80)}")
        print(f"Eigene Domain:    {sanitize_field(r['domain'], 80)}")
        print(f"Quell-IP:         {r['source_ip']}")
        print(f"Anzahl:           {r['count']}")
        print(f"Disposition:      {sanitize_field(r['disposition'], 20)}")
        print(f"DKIM:             {sanitize_field(r['dkim_result'], 20)}")
        print(f"SPF:              {sanitize_field(r['spf_result'], 20)}")
        print(f"Header-From:      {sanitize_field(r['header_from'], 80)}")
        print(f"Envelope-To:      {sanitize_field(r['envelope_to'], 80)}")
        print(f"Envelope-From:    {sanitize_field(r['envelope_from'], 80)}")
        print(f"Eigene IP:        {'ja' if r['is_own_ip'] else 'nein'}")
        if r["is_flagged"]:
            labels = ", ".join(REASON_LABELS_DE.get(x, x) for x in reasons)
            print(f"Auffällig:        ja - {labels}")
        else:
            print("Auffällig:        nein")
        if args.whois:
            ip = r["source_ip"]
            if ip not in whois_cache:
                try:
                    org = lookup_ip_organization(ip)
                    if org:
                        whois_cache[ip] = org
                        # In der lokalen DB ablegen, damit die Menüleisten-App
                        # das später nur lesen kann, ohne selbst rdap.org
                        # anzufragen - siehe get_all_cached_whois().
                        set_cached_whois(db_conn, ip, org)
                    else:
                        whois_cache[ip] = "unbekannt"
                except WhoisLookupError as exc:
                    # Fehlschläge werden bewusst NICHT gecacht - ein
                    # vorübergehender Netzwerkfehler soll nicht dauerhaft als
                    # Ergebnis hängen bleiben, ein späterer Versuch soll es
                    # erneut probieren.
                    whois_cache[ip] = f"Abfrage fehlgeschlagen ({exc})"
                    inline_lookup_failed = True
                    print(f"WHOIS-Abfrage fehlgeschlagen: {exc}", file=sys.stderr)
            print(f"WHOIS-Organisation (nur Hinweis, keine Einstufung): {whois_cache[ip]}")
        if args.blacklist:
            ip = r["source_ip"]
            if ip not in blacklist_cache:
                try:
                    result = check_ip_blacklist(ip)
                    if result.listed:
                        blacklist_cache[ip] = "gelistet - " + "; ".join(result.reasons)
                    else:
                        blacklist_cache[ip] = "nicht gelistet"
                    # In der lokalen DB ablegen, damit die Menüleisten-App
                    # das später nur lesen kann, ohne selbst Spamhaus
                    # anzufragen - siehe get_all_cached_blacklist().
                    set_cached_blacklist(db_conn, ip, result.listed, result.reasons)
                except BlacklistCheckError as exc:
                    # Fehlschläge werden bewusst NICHT gecacht - siehe
                    # WHOIS-Kommentar oben, gleicher Grund.
                    blacklist_cache[ip] = f"Abfrage fehlgeschlagen ({exc})"
                    inline_lookup_failed = True
                    print(f"Spamhaus-Abfrage fehlgeschlagen: {exc}", file=sys.stderr)
            print(f"Spamhaus ZEN (nur Hinweis, keine Einstufung): {blacklist_cache[ip]}")
    db_conn.close()
    print("=" * 60)
    print(f"{len(matches)} Treffer für {args.query!r} in den letzten {args.days} Tagen.")
    # Exit-Code 3: Treffer wurden gefunden und angezeigt, aber mindestens
    # eine angeforderte --whois/--blacklist-Abfrage ist fehlgeschlagen (ohne
    # Caching, siehe oben) - eigener Code statt 0 (voller Erfolg) oder 1
    # (keine Treffer), damit Aufrufer wie die Menüleisten-App das ohne
    # Textabgleich unterscheiden können (siehe StatusBarController.swift).
    return 3 if inline_lookup_failed else 0


def cmd_menubar(args: argparse.Namespace) -> int:
    config = load_config()
    db_conn = connect(db_path())
    since_ts, until_ts = day_range_to_ts(config.menubar_days)
    rows = collect_rows(db_conn, since_ts, until_ts)
    db_conn.close()
    sys.stdout.write(render_swiftbar(rows, config.menubar_days))
    return 0


def cmd_menubar_json(args: argparse.Namespace) -> int:
    """Strukturierte JSON-Ausgabe für native Konsumenten (z. B. die
    Swift-Menüleisten-App), im Gegensatz zu 'menubar' (SwiftBar-Textformat).

    Liest ggf. vorhandene WHOIS-Cache-Einträge nur aus der lokalen DB (siehe
    get_all_cached_whois) - macht selbst nie eine Netzwerkanfrage. Nur
    `dmarcwatch inspect --whois` füllt diesen Cache."""
    config = load_config()
    db_conn = connect(db_path())
    since_ts, until_ts = day_range_to_ts(config.menubar_days)
    rows = collect_rows(db_conn, since_ts, until_ts)
    whois_by_ip = get_all_cached_whois(db_conn)
    blacklist_by_ip = get_all_cached_blacklist(db_conn)
    db_conn.close()
    skipped_items = read_skipped_items()
    dns_check = read_dns_check_result()
    json.dump(
        to_json_dict(rows, config.menubar_days, whois_by_ip, skipped_items, dns_check, blacklist_by_ip),
        sys.stdout,
    )
    sys.stdout.write("\n")
    return 0


def cmd_resolve_spf(args: argparse.Namespace) -> int:
    """JSON-Ausgabe für den "Aus SPF ermitteln"-Knopf im Setup-Fenster der
    Menüleisten-App (SetupViewModel.swift) - nicht für den interaktiven
    Gebrauch gedacht. Löst den SPF-Eintrag der übergebenen Domain per DNS
    auf (siehe spf.py) und liefert einen Vorschlag für own_ip_networks;
    die GUI trägt das Ergebnis nur zur Kontrolle/Bearbeitung ins Formular
    ein, speichert es nie automatisch ungesehen."""
    try:
        networks = resolve_own_ip_networks(args.domain)
    except SPFResolutionError as exc:
        json.dump({"error": str(exc)}, sys.stdout)
        sys.stdout.write("\n")
        return 1
    json.dump({"domain": args.domain, "networks": networks}, sys.stdout)
    sys.stdout.write("\n")
    return 0


def _print_verify_result(result: DomainVerification) -> None:
    print(f"Domain: {result.domain}")
    print()

    print("DMARC (_dmarc." + result.domain + ")")
    if not result.dmarc.exists:
        print("  Kein Eintrag gefunden.")
    else:
        print(f"  Policy (p):        {result.dmarc.policy}")
        if result.dmarc.subdomain_policy:
            print(f"  Subdomain (sp):    {result.dmarc.subdomain_policy}")
        if result.dmarc.pct is not None:
            print(f"  Prozent (pct):     {result.dmarc.pct}")
        print(f"  rua:               {result.dmarc.rua or '(nicht gesetzt)'}")
        print(f"  ruf:               {result.dmarc.ruf or '(nicht gesetzt)'}")
        print(f"  Alignment (adkim/aspf): {result.dmarc.adkim}/{result.dmarc.aspf}")
    for warning in result.dmarc.warnings:
        print(f"  ⚠ {warning}")

    print()
    print("SPF")
    if not result.spf.exists:
        print("  Kein Eintrag gefunden." if result.spf.error is None else f"  Fehler: {result.spf.error}")
    else:
        print(f"  Eintrag:           {result.spf.record}")
        print(f"  DNS-Lookups:       {result.spf.lookup_count}/10")
    for warning in result.spf.warnings:
        print(f"  ⚠ {warning}")

    print()
    print("DKIM")
    if not result.dkim:
        print(
            "  Keine bekannten Selektoren - werden aus bereits abgerufenen Reports gelernt "
            "(siehe `dmarcwatch fetch`), noch keine vorhanden für diese Domain."
        )
    for dkim_result in result.dkim:
        status = "gefunden" if dkim_result.exists else "NICHT gefunden"
        key_info = f", Typ: {dkim_result.key_type}" if dkim_result.key_type else ""
        print(f"  Selektor {dkim_result.selector!r}: {status}{key_info}")
        for warning in dkim_result.warnings:
            print(f"    ⚠ {warning}")

    # MTA-STS/TLS-RPT-DNS/Wildcard-SPF sind optional - nur ausgeben, wenn
    # tatsächlich etwas konfiguriert ist, sonst unnötiges Rauschen für die
    # meisten Domains, die das gar nicht nutzen.
    if result.mta_sts.configured:
        print()
        print(f"MTA-STS (mta-sts.{result.domain} / _mta-sts.{result.domain})")
        print(f"  Ziel:              {result.mta_sts.cname_target or '(A/AAAA statt CNAME)'}")
        print(f"  Policy-Eintrag:    {result.mta_sts.policy_txt or '(nicht gefunden)'}")
        if result.mta_sts.policy_reachable is not None:
            status = "erreichbar" if result.mta_sts.policy_reachable else "NICHT erreichbar"
            print(f"  Policy-Datei:      {status} (https://mta-sts.{result.domain}/.well-known/mta-sts.txt)")
        for warning in result.mta_sts.warnings:
            print(f"  ⚠ {warning}")

    if result.tlsrpt_dns.configured:
        print()
        print(f"TLS-RPT-DNS (_smtp._tls.{result.domain})")
        print(f"  Eintrag:           {result.tlsrpt_dns.record}")
        for warning in result.tlsrpt_dns.warnings:
            print(f"  ⚠ {warning}")

    if result.wildcard_spf.configured:
        print()
        print(f"Wildcard-SPF (*.{result.domain})")
        print(f"  Eintrag:           {result.wildcard_spf.record}")
        for warning in result.wildcard_spf.warnings:
            print(f"  ⚠ {warning}")

    if result.dnssec.configured:
        print()
        print(f"DNSSEC ({result.domain})")
        if result.dnssec.validated is not None:
            status = "gültig" if result.dnssec.validated else "NICHT gültig"
            print(f"  Validierung:       {status} (über {_DNSSEC_VALIDATING_RESOLVER})")
        for warning in result.dnssec.warnings:
            print(f"  ⚠ {warning}")

    if result.dane.configured:
        print()
        print(f"DANE/TLSA ({result.domain})")
        print(f"  MX mit TLSA:       {', '.join(result.dane.mx_hosts_with_tlsa)}")
        for warning in result.dane.warnings:
            print(f"  ⚠ {warning}")

    if result.bimi.configured:
        print()
        print(f"BIMI (default._bimi.{result.domain})")
        print(f"  Eintrag:           {result.bimi.record}")
        if result.bimi.logo_reachable is not None:
            status = "erreichbar" if result.bimi.logo_reachable else "NICHT erreichbar"
            print(f"  Logo-Datei:        {status}")
        for warning in result.bimi.warnings:
            print(f"  ⚠ {warning}")

    if result.mx_blacklist.checked:
        print()
        print("Mailserver-Blacklist (Spamhaus ZEN)")
        print(f"  MX-Server:         {', '.join(result.mx_blacklist.mx_hosts)}")
        status = "gelistet" if result.mx_blacklist.listed else "sauber"
        print(f"  Status:            {status}")
        for warning in result.mx_blacklist.warnings:
            print(f"  ⚠ {warning}")


def _verification_to_dict(result: DomainVerification) -> dict:
    """JSON-Repräsentation für den `--json`-Modus - von der Menüleisten-App
    genutzt (DNSVerifyView.swift), um das Ergebnis nativ darzustellen statt
    die menschenlesbare Textausgabe zu parsen."""
    return {
        "domain": result.domain,
        "dmarc": {
            "exists": result.dmarc.exists,
            "record": result.dmarc.record,
            "policy": result.dmarc.policy,
            "subdomain_policy": result.dmarc.subdomain_policy,
            "pct": result.dmarc.pct,
            "rua": result.dmarc.rua,
            "ruf": result.dmarc.ruf,
            "adkim": result.dmarc.adkim,
            "aspf": result.dmarc.aspf,
            "warnings": result.dmarc.warnings,
        },
        "spf": {
            "exists": result.spf.exists,
            "record": result.spf.record,
            "lookup_count": result.spf.lookup_count,
            "lookup_limit_ok": result.spf.lookup_limit_ok,
            "warnings": result.spf.warnings,
            "error": result.spf.error,
        },
        "dkim": [
            {
                "selector": d.selector,
                "exists": d.exists,
                "key_type": d.key_type,
                "warnings": d.warnings,
            }
            for d in result.dkim
        ],
        "mta_sts": {
            "configured": result.mta_sts.configured,
            "cname_target": result.mta_sts.cname_target,
            "policy_txt": result.mta_sts.policy_txt,
            "policy_reachable": result.mta_sts.policy_reachable,
            "warnings": result.mta_sts.warnings,
        },
        "tlsrpt_dns": {
            "configured": result.tlsrpt_dns.configured,
            "record": result.tlsrpt_dns.record,
            "warnings": result.tlsrpt_dns.warnings,
        },
        "wildcard_spf": {
            "configured": result.wildcard_spf.configured,
            "record": result.wildcard_spf.record,
            "warnings": result.wildcard_spf.warnings,
        },
        "dnssec": {
            "configured": result.dnssec.configured,
            "validated": result.dnssec.validated,
            "warnings": result.dnssec.warnings,
        },
        "dane": {
            "configured": result.dane.configured,
            "mx_hosts_with_tlsa": result.dane.mx_hosts_with_tlsa,
            "warnings": result.dane.warnings,
        },
        "bimi": {
            "configured": result.bimi.configured,
            "record": result.bimi.record,
            "logo_svg": result.bimi.logo_svg,
            "logo_reachable": result.bimi.logo_reachable,
            "warnings": result.bimi.warnings,
        },
        "mx_blacklist": {
            "checked": result.mx_blacklist.checked,
            "mx_hosts": result.mx_blacklist.mx_hosts,
            "listed": result.mx_blacklist.listed,
            "warnings": result.mx_blacklist.warnings,
        },
    }


def _run_dns_check_and_persist(domains: list[str]) -> list[DomainVerification]:
    """Führt verify_domain() für alle domains aus und speichert das Ergebnis
    (überschreibt die vorherige Datei komplett, kein wachsendes Protokoll) -
    von cmd_verify_dns (Klick auf "DNS prüfen…" oder Terminal-Aufruf) UND
    vom periodischen automatischen Check in cmd_fetch genutzt, damit die
    Menüleisten-App unabhängig vom Auslöser immer den letzten bekannten
    Stand anzeigen kann, ohne selbst eine DNS-Abfrage zu machen."""
    db_conn = connect(db_path())
    try:
        results = [verify_domain(db_conn, domain) for domain in domains]
    finally:
        db_conn.close()

    write_dns_check_result(
        {
            "checked_at": time.strftime("%Y-%m-%d"),
            "domains": [
                {**_verification_to_dict(r), "has_warnings": has_warnings(r)} for r in results
            ],
        }
    )
    return results


def cmd_verify_dns(args: argparse.Namespace) -> int:
    """Prüft die eigenen DMARC/SPF/DKIM-DNS-Einträge auf Gültigkeit und
    häufige Fehlkonfigurationen (siehe dns_verify.py) - verlässt das Gerät
    (DNS). Läuft entweder auf ausdrücklichen Klick/Terminal-Aufruf, oder
    periodisch automatisch über `fetch`, wenn `enable_auto_dns_check`
    aktiv ist (einmalige Zustimmung per Checkbox, siehe cmd_fetch)."""
    if args.domain:
        domains = [args.domain]
    else:
        config = load_config()
        domains = list(config.own_domains)
        if not domains:
            print(
                "Fehler: keine own_domains konfiguriert und keine Domain angegeben.",
                file=sys.stderr,
            )
            return 2

    results = _run_dns_check_and_persist(domains)

    if args.json:
        json.dump([_verification_to_dict(r) for r in results], sys.stdout)
        sys.stdout.write("\n")
    else:
        # Genau eine "="-Trennlinie vor jeder Domain (dient gleichzeitig als
        # Trenner zur vorherigen) statt einer schließenden pro Domain in
        # _print_verify_result selbst - sonst stehen bei mehreren Domains
        # zwei Trennlinien direkt hintereinander.
        for result in results:
            print("=" * 60)
            _print_verify_result(result)
        print("=" * 60)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dmarcwatch", description="Lokaler DMARC-Monitor für macOS")
    sub = parser.add_subparsers(dest="command", required=True)

    p_setup = sub.add_parser("setup", help="Konfiguration, Schlüsselbund und LaunchAgent einrichten")
    p_setup.add_argument("--install-agent", action="store_true", help="fetch-LaunchAgent installieren (täglich)")
    p_setup.add_argument("--remove-agent", action="store_true", help="fetch-LaunchAgent entfernen")
    p_setup.add_argument(
        "--hour", type=int, default=None,
        help="Stunde für den täglichen Lauf (0-23). Ohne Angabe: interaktiv abgefragt."
    )
    p_setup.add_argument(
        "--minute", type=int, default=None,
        help="Minute für den täglichen Lauf (0-59). Ohne Angabe: interaktiv abgefragt."
    )
    p_setup.add_argument(
        "--reset-password", action="store_true",
        help="Schlüsselbund-Passwort neu eingeben, auch wenn schon eines gespeichert ist"
    )
    p_setup.add_argument(
        "--reconfigure", action="store_true",
        help="IMAP-Server/Login/Domain(s) erneut interaktiv abfragen, auch wenn schon konfiguriert"
    )
    p_setup.add_argument(
        "--remove-menubar-agent", action="store_true",
        help=(
            "Alten, plist-basierten Menüleisten-LaunchAgent entfernen (Migrationshilfe - "
            "die App registriert sich seit der SMAppService-Umstellung selbst)"
        ),
    )
    p_setup.add_argument(
        "--from-stdin-json", action="store_true",
        help=(
            "Konfiguration (und optional Passwort) als JSON-Objekt von stdin lesen statt "
            "interaktiv abzufragen - für die native Setup-GUI, nicht für den Handgebrauch gedacht"
        ),
    )
    p_setup.set_defaults(func=cmd_setup)

    p_fetch = sub.add_parser("fetch", help="Neue Reports per IMAP abrufen und verarbeiten")
    p_fetch.add_argument("-v", "--verbose", action="store_true")
    p_fetch.add_argument(
        "--skip-if-already-run-today", action="store_true",
        help=(
            "Überspringen, wenn heute schon ein erfolgreicher Abruf lief - für den "
            "LaunchAgent gedacht (RunAtLoad), damit ein wegen ausgeschaltetem Mac "
            "verpasster Zeitplan beim nächsten Start nachgeholt wird, ohne bei jedem "
            "Login unnötig doppelt per IMAP nachzusehen. 'Jetzt abrufen' und ein von "
            "Hand getipptes 'dmarcwatch fetch' lassen das bewusst weg."
        ),
    )
    p_fetch.set_defaults(func=cmd_fetch)

    p_report = sub.add_parser("report", help="Tabellarische Zusammenfassung anzeigen")
    p_report.add_argument("--days", type=int, default=7, help="Zeitraum in Tagen (Default: 7)")
    p_report.set_defaults(func=cmd_report)

    p_tls_report = sub.add_parser(
        "tls-report", help="Tabellarische Zusammenfassung der TLS-RPT-Reports anzeigen"
    )
    p_tls_report.add_argument("--days", type=int, default=7, help="Zeitraum in Tagen (Default: 7)")
    p_tls_report.add_argument("--json", action="store_true", help="Ausgabe als JSON statt Tabelle")
    p_tls_report.set_defaults(func=cmd_tls_report)

    p_stats = sub.add_parser(
        "stats", help="Tagestrend und Verschärfungs-Einschätzung (DMARC/MTA-STS) anzeigen"
    )
    # 30 statt 7 Tage Default - für eine sinnvolle Verschärfungs-Einschätzung
    # braucht es mehr als eine Woche Beobachtungszeitraum.
    p_stats.add_argument("--days", type=int, default=30, help="Zeitraum in Tagen (Default: 30)")
    p_stats.add_argument("--json", action="store_true", help="Ausgabe als JSON statt Tabelle")
    p_stats.set_defaults(func=cmd_stats)

    p_inspect = sub.add_parser(
        "inspect", help="Vollständige Details zu einer IP oder einem CIDR-Netz anzeigen"
    )
    p_inspect.add_argument("query", help="IP-Adresse oder CIDR-Netz, z. B. 2a01:111::/32")
    p_inspect.add_argument("--days", type=int, default=90, help="Zeitraum in Tagen (Default: 90)")
    p_inspect.add_argument(
        "--whois", action="store_true",
        help="Zusätzlich WHOIS/RDAP-Organisation der IP abfragen (verlässt das Gerät; "
        "rein informativ, ändert nie die Auffälligkeits-Einstufung)"
    )
    p_inspect.add_argument(
        "--blacklist", action="store_true",
        help="Zusätzlich gegen Spamhaus ZEN prüfen (verlässt das Gerät; "
        "rein informativ, ändert nie die Auffälligkeits-Einstufung, nur IPv4)"
    )
    p_inspect.set_defaults(func=cmd_inspect)

    p_menubar = sub.add_parser("menubar", help="SwiftBar-Ausgabe erzeugen")
    p_menubar.set_defaults(func=cmd_menubar)

    p_menubar_json = sub.add_parser(
        "menubar-json", help="Strukturierte JSON-Ausgabe für native Konsumenten (z. B. die Swift-App)"
    )
    p_menubar_json.set_defaults(func=cmd_menubar_json)

    p_resolve_spf = sub.add_parser(
        "resolve-spf",
        help=(
            "SPF-Eintrag einer Domain per DNS auflösen (include:/redirect=/a/mx), JSON-Ausgabe "
            "für den 'Aus SPF ermitteln'-Knopf in der Setup-GUI - verlässt das Gerät (DNS)"
        ),
    )
    p_resolve_spf.add_argument("domain")
    p_resolve_spf.set_defaults(func=cmd_resolve_spf)

    p_verify_dns = sub.add_parser(
        "verify-dns",
        help=(
            "Eigenen DMARC/SPF/DKIM-DNS-Eintrag auf Gültigkeit und häufige "
            "Fehlkonfigurationen prüfen - verlässt das Gerät (DNS)"
        ),
    )
    p_verify_dns.add_argument(
        "domain", nargs="?", default=None,
        help="Zu prüfende Domain (Default: alle own_domains aus der Konfiguration)",
    )
    p_verify_dns.add_argument(
        "--json", action="store_true",
        help="JSON statt menschenlesbarem Text ausgeben (für die Menüleisten-App)",
    )
    p_verify_dns.set_defaults(func=cmd_verify_dns)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
