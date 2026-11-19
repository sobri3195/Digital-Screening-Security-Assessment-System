from datetime import date
from ipaddress import ip_address
import re
from typing import Annotated, Literal
from urllib.parse import urlsplit

import idna
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


Cve = Annotated[str, StringConstraints(to_upper=True, pattern=r"^CVE-[0-9]{4}-[0-9]{4,19}$")]
Digest = Annotated[str, StringConstraints(to_lower=True, pattern=r"^[a-f0-9]{64}$")]
ModelName = Annotated[
    str, StringConstraints(min_length=1, max_length=96, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.:/-]*$")
]
Technology = Literal["windows", "android", "ios", "network", "linux"]
Status = Literal["pass", "fail", "unknown", "not_applicable"]
Severity = Literal["informational", "low", "medium", "high", "critical", "unknown"]
Topic = Literal["vulnerability", "phishing", "malware", "configuration", "education", "incident", "advisory"]
Control = Literal["firewall", "antivirus", "updates", "encryption", "secure_boot", "support"]
Action = Literal[
    "verify_source",
    "verify_version",
    "apply_patch",
    "review_firewall",
    "review_antivirus",
    "review_encryption",
    "review_updates",
    "review_secure_boot",
    "review_support",
    "contain_file",
    "escalate_incident",
    "reinspect",
    "verify_domain",
    "review_advisory",
]
CORE_SCOPES = frozenset(
    {
        "ai.dashboard.view",
        "ai.analysis.execute",
        "ai.threat.analyze",
        "ai.vulnerability.analyze",
        "ai.malware.analyze",
        "ai.configuration.analyze",
        "ai.mitigation.generate",
        "ai.report.generate",
        "ai.report.review",
        "ai.knowledge.view",
        "ai.knowledge.manage",
        "ai.knowledge.approve",
        "ai.model.manage",
        "ai.template.manage",
        "ai.template.approve",
        "ai.evaluation.execute",
        "ai.audit.view",
        "ai.settings.manage",
    }
)
SCOPE = {
    "threat": "ai.threat.analyze",
    "vulnerability": "ai.vulnerability.analyze",
    "malware": "ai.malware.analyze",
    "configuration": "ai.configuration.analyze",
    "mitigation": "ai.mitigation.generate",
    "report": "ai.report.generate",
    "executive": "ai.report.generate",
    "advisory": "ai.threat.analyze",
    "education": "ai.threat.analyze",
    "correlation": "ai.threat.analyze",
}
TRUSTED_SOURCES = {
    "cisa": ("CISA KEV", ("cisa.gov",)),
    "nist": ("NIST NVD", ("nist.gov",)),
    "first": ("FIRST EPSS", ("first.org",)),
    "mitre": ("MITRE dan CWE", ("mitre.org", "cve.org")),
    "owasp": ("OWASP", ("owasp.org",)),
    "bssn": ("BSSN", ("bssn.go.id",)),
    "kemkes": ("Kemenkes CSIRT", ("kemkes.go.id",)),
    "vendor": (
        "Advisori vendor",
        ("microsoft.com", "apple.com", "android.com", "google.com", "ubuntu.com", "redhat.com"),
    ),
    "internal": ("Dokumentasi internal", ()),
}


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def indicator_value(kind: str, text: str) -> str:
    if not text or len(text) > 320 or re.search(r"[\x00-\x20\x7f\\]", text):
        raise ValueError("indicator")
    if kind == "hash" and re.fullmatch(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", text):
        return text.lower()
    if kind == "ip":
        return ip_address(text).compressed if "%" not in text else _invalid()
    if kind == "cve" and re.fullmatch(r"CVE-\d{4}-\d{4,19}", text.upper(), re.ASCII):
        return text.upper()
    if kind == "url":
        parts = urlsplit(text)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.path not in ("", "/")
            or "?" in text
            or "#" in text
            or parts.port is not None
        ):
            raise ValueError("origin-only URL")
        return indicator_value("domain", parts.hostname)
    if kind == "domain":
        host = idna.encode(text.rstrip("."), uts46=True, std3_rules=True).decode("ascii").lower()
        if "." in host and len(host) <= 253 and not re.fullmatch(r"[0-9.]+", host):
            return host
    raise ValueError("indicator")


def _invalid():
    raise ValueError("indicator")


class Indicator(Input):
    type: Literal["domain", "ip", "url", "hash", "cve"]
    indicator: Annotated[str, StringConstraints(max_length=320)]

    @model_validator(mode="after")
    def normalize(self):
        self.indicator = indicator_value(self.type, self.indicator)
        if self.type == "url":
            self.type = "domain"
        return self


class Threat(Indicator):
    kind: Literal["threat", "correlation"]


class Vulnerability(Input):
    kind: Literal["vulnerability"]
    cve: Cve


class Malware(Input):
    kind: Literal["malware"]
    sha256: Digest
    verdict: Literal["unknown", "no_indicators", "review", "detected", "unavailable"] = "unknown"
    engine: Literal["unknown", "defender", "clamav", "yara", "catalog"] = "unknown"


class Configuration(Input):
    kind: Literal["configuration"]
    platform: Technology
    controls: Annotated[dict[Control, Status], Field(min_length=1, max_length=6)]


class Mitigation(Input):
    kind: Literal["mitigation"]
    category: Topic
    cve: Cve | None = None


class Education(Input):
    kind: Literal["education"]
    topic: Literal["ioc", "cvss_epss", "phishing", "patching"]


class Advisory(Input):
    kind: Literal["advisory"]
    document_id: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]


Count = Annotated[int, Field(strict=True, ge=0, le=100000000)]


class Report(Input):
    kind: Literal["report", "executive"]
    period: Literal["current", "monthly", "annual"]
    assets: Count
    critical_vulnerabilities: Count
    active_incidents: Count
    observed_malware: Count
    pending_mitigations: Count | None = None
    previous_critical: Count | None = None


Analysis = Annotated[
    Threat | Vulnerability | Malware | Configuration | Mitigation | Education | Advisory | Report,
    Field(discriminator="kind"),
]


class Facts(Input):
    topic: Topic
    cve: Cve | None = None
    cvss: Annotated[float, Field(ge=0, le=10, allow_inf_nan=False)] | None = None
    cwe: Annotated[str, StringConstraints(pattern=r"^CWE-[0-9]{1,7}$")] | None = None
    epss: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)] | None = None
    epss_on: date | None = None
    severity: Severity = "unknown"
    kev: bool | None = None
    known_indicator: Indicator | None = None
    actions: Annotated[list[Action], Field(max_length=6)] = []

    @model_validator(mode="after")
    def consistency(self):
        if (self.epss is None) != (self.epss_on is None):
            raise ValueError("EPSS date required")
        if self.cve is None and any(x is not None for x in (self.cvss, self.epss, self.cwe, self.kev)):
            raise ValueError("CVE required")
        return self


class Document(Input):
    title: Annotated[str, StringConstraints(min_length=3, max_length=150)]
    source: Annotated[str, StringConstraints(max_length=30)]
    version: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.-]{1,24}$")]
    published: date
    reference: Annotated[str, StringConstraints(min_length=3, max_length=360)]
    classification: Literal["public", "internal_technical"]
    content: Annotated[str, StringConstraints(min_length=20, max_length=64000)]
    facts: Facts

    @model_validator(mode="after")
    def source_reference(self):
        if self.source not in TRUSTED_SOURCES:
            raise ValueError("source")
        if self.source == "internal":
            if self.classification != "internal_technical" or not re.fullmatch(
                r"REF-[A-Z0-9-]{2,60}", self.reference
            ):
                raise ValueError("reference")
        else:
            domains = TRUSTED_SOURCES[self.source][1]
            parsed = urlsplit(self.reference)
            if (
                self.classification != "public"
                or parsed.scheme != "https"
                or parsed.username is not None
                or parsed.query
                or parsed.fragment
                or parsed.port is not None
                or not any(parsed.hostname == h or (parsed.hostname or "").endswith("." + h) for h in domains)
            ):
                raise ValueError("reference")
        # The approval step remains the primary control for technical-only document content.
        if re.search(
            r"-----BEGIN .*PRIVATE KEY-----|\bBearer\s+[a-z0-9_.-]{18,}|\b0[89][0-9]{9,12}\b|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
            self.content + " " + self.title,
            re.IGNORECASE,
        ):
            raise ValueError("possible personal data or credential")
        return self


class Approval(Input):
    reviewed: Literal[True]


class ModelApproval(Input):
    name: ModelName
    role: Literal["inference", "embedding"]
    license_reference: Annotated[
        str, StringConstraints(pattern=r"^https://[a-zA-Z0-9.-]+/[^\s?#]+$", max_length=300)
    ]
    reviewed: Literal[True]


class ModelOptions(Input):
    context: Annotated[int, Field(ge=1024, le=8192)] = 4096
    temperature: Annotated[float, Field(ge=0, le=1)] = 0
    top_p: Annotated[float, Field(gt=0, le=1)] = 0.9
    max_output: Annotated[int, Field(ge=64, le=512)] = 320
    device: Literal["cpu", "auto"] = "auto"


class Review(Input):
    decision: Literal["verified", "needs_revision", "incorrect"]
