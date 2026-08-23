"""Datenmodell für DMARC Aggregate Reports (RFC 7489)."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ReportMetadata:
    org_name: str
    report_id: str
    date_begin: int
    date_end: int
    email: str = ""


@dataclass(frozen=True)
class PolicyPublished:
    domain: str
    p: str
    sp: str = ""
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"
    # Policy für nicht existierende Subdomains (RFC 9091 / DMARCbis). Fehlt
    # das Feld, erbt es von sp bzw. p - hier wird nur festgehalten, was der
    # Report tatsächlich meldet, keine eigene Vererbungslogik.
    np: str = ""


@dataclass(frozen=True)
class DKIMAuthResult:
    domain: str
    selector: str
    result: str


@dataclass(frozen=True)
class SPFAuthResult:
    domain: str
    result: str


@dataclass(frozen=True)
class AuthResults:
    dkim: tuple[DKIMAuthResult, ...] = field(default_factory=tuple)
    spf: tuple[SPFAuthResult, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Identifiers:
    header_from: str
    envelope_to: str = ""
    envelope_from: str = ""


@dataclass(frozen=True)
class PolicyEvaluated:
    disposition: str
    dkim: str
    spf: str


@dataclass(frozen=True)
class Record:
    source_ip: str
    count: int
    policy_evaluated: PolicyEvaluated
    identifiers: Identifiers
    auth_results: AuthResults


@dataclass(frozen=True)
class AggregateReport:
    metadata: ReportMetadata
    policy_published: PolicyPublished
    records: tuple[Record, ...]


@dataclass(frozen=True)
class TLSReportMetadata:
    organization_name: str
    report_id: str
    date_begin: int
    date_end: int
    contact_info: str = ""


@dataclass(frozen=True)
class TLSPolicy:
    policy_type: str
    policy_domain: str
    policy_strings: tuple[str, ...] = field(default_factory=tuple)
    mx_host: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class TLSFailureDetail:
    result_type: str
    sending_mta_ip: str = ""
    receiving_mx_hostname: str = ""
    receiving_mx_helo: str = ""
    receiving_ip: str = ""
    failed_session_count: int = 0
    additional_information: str = ""
    failure_reason_code: str = ""


@dataclass(frozen=True)
class TLSPolicyResult:
    policy: TLSPolicy
    successful_session_count: int
    failure_count: int
    failure_details: tuple[TLSFailureDetail, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class TLSReport:
    metadata: TLSReportMetadata
    policy_results: tuple[TLSPolicyResult, ...]
