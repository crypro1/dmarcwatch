"""CLI-Einstiegspunkt: dmarcwatch setup|fetch|report|menubar."""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time

from . import keychain, launchd, notify
from .anomaly import REASON_LABELS_DE
from .config import (
    Config,
    config_path,
    db_path,
    load_config,
    log_path,
    read_last_fetch_date,
    read_raw_config,
    write_config,
    write_default_config_if_missing,
    write_last_fetch_date,
)
from .fetch import FetchError, connect_imap, fetch_and_ingest
from .logging_setup import setup_logging
from .report import collect_rows, day_range_to_ts, format_table, has_findings, to_json_dict
from .menubar import render_swiftbar
from .sanitize import sanitize_field
from .store import connect, get_all_cached_whois, query_records, set_cached_whois
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

    if config.notify_on_new_findings and summary.flagged_count > 0:
        notify.send_notification(
            title="DMARC Auffälligkeit",
            message=f"{summary.flagged_count} auffällige Einträge in neuen Reports",
        )

    return 1 if summary.flagged_count > 0 else 0


def cmd_report(args: argparse.Namespace) -> int:
    db_conn = connect(db_path())
    since_ts, until_ts = day_range_to_ts(args.days)
    rows = collect_rows(db_conn, since_ts, until_ts)
    db_conn.close()
    print(format_table(rows))
    return 1 if has_findings(rows) else 0


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
            print(f"WHOIS-Organisation (nur Hinweis, keine Einstufung): {whois_cache[ip]}")
    db_conn.close()
    print("=" * 60)
    print(f"{len(matches)} Treffer für {args.query!r} in den letzten {args.days} Tagen.")
    return 0


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
    db_conn.close()
    json.dump(to_json_dict(rows, config.menubar_days, whois_by_ip), sys.stdout)
    sys.stdout.write("\n")
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
    p_inspect.set_defaults(func=cmd_inspect)

    p_menubar = sub.add_parser("menubar", help="SwiftBar-Ausgabe erzeugen")
    p_menubar.set_defaults(func=cmd_menubar)

    p_menubar_json = sub.add_parser(
        "menubar-json", help="Strukturierte JSON-Ausgabe für native Konsumenten (z. B. die Swift-App)"
    )
    p_menubar_json.set_defaults(func=cmd_menubar_json)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
