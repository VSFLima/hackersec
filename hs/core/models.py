"""Modelos canonicos: Asset e Finding.

Toda a ferramenta converte a saida bruta de cada check num `Finding` unico,
com fingerprint estavel, para deduplicar e agrupar por CWE/severidade.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any
from urllib.parse import urlsplit, urlunsplit


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    @property
    def label(self) -> str:
        return self.value.capitalize()


_SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}

_SEVERITY_BY_MEMBER = {
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
}


def severity_from(text: Any) -> Severity:
    if isinstance(text, Severity):
        return text
    raw = getattr(text, "value", text)
    key = str(raw or "").strip().lower()
    if key in _SEVERITY_BY_MEMBER:
        return _SEVERITY_BY_MEMBER[key]
    return Severity.LOW


def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower().rstrip(".")
    if host.startswith("www.") and len(host) > 4:
        host = host[4:]
    port = parts.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = re.sub(r"/{2,}", "/", parts.path) or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


@dataclass
class Asset:
    """Ativo descoberto."""

    host: str = ""
    url: str = ""
    port: int | None = None
    scheme: str = ""
    status: int | None = None
    title: str = ""
    server: str = ""
    tech: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    is_live: bool = False
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.host = (self.host or "").strip().lower().rstrip(".")
        if not self.url and self.host:
            self.url = f"{self.scheme or 'http'}://{self.host}"
        if self.url and not self.scheme:
            self.scheme = urlsplit(self.url).scheme or "http"
        if not self.port and self.url:
            self.port = urlsplit(self.url).port
        if not self.host and self.url:
            self.host = urlsplit(self.url).hostname or ""
        self.tech = sorted({t.strip().lower() for t in self.tech if t and t.strip()})

    @property
    def key(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port or _default_port(self.scheme)}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Asset":
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass
class Finding:
    """Achado normalizado, pronto para relatorio."""

    check_id: str
    title: str
    severity: Severity = Severity.LOW
    asset: str = ""
    url: str = ""
    cwe: str = ""
    cve: str = ""
    cvss: float | None = None
    description: str = ""
    impact: str = ""
    steps: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    source: str = "hackersec"
    confidence: str = "medium"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.check_id = (self.check_id or "").strip().lower()
        self.title = (self.title or "").strip()
        self.severity = severity_from(self.severity)
        if self.url:
            self.url = normalize_url(self.url)
            if not self.asset:
                self.asset = urlsplit(self.url).hostname or ""
        self.asset = (self.asset or "").strip().lower()
        self.cwe = _norm_cwe(self.cwe)
        self.cve = self.cve.strip().upper()
        if self.cvss is not None:
            self.cvss = round(max(0.0, min(10.0, float(self.cvss))), 1)
        self.tags = sorted({t.strip().lower() for t in self.tags if t and t.strip()})

    @property
    def fingerprint(self) -> str:
        parts = [self.check_id, self.asset, _stable_path(self.url)]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]

    @property
    def key(self) -> str:
        return f"{self.check_id}|{self.asset}|{_stable_path(self.url)}"

    @property
    def group_key(self) -> str:
        return f"{self.cwe or self.check_id}|{self.severity.value}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["fingerprint"] = self.fingerprint
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        data = dict(data)
        data.pop("fingerprint", None)
        data.pop("key", None)
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in allowed})


class FindingSet:
    """Colecao deduplicada de findings."""

    def __init__(self, findings: list[Finding] | None = None) -> None:
        self._items: dict[str, Finding] = {}
        for finding in findings or []:
            self.add(finding)

    def __iter__(self):
        return iter(self._items.values())

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return bool(self._items)

    def add(self, finding: Finding) -> bool:
        """Adiciona. Retorna False se ja existia um igual (dedup)."""
        if finding.key in self._items:
            return False
        self._items[finding.key] = finding
        return True

    def extend(self, findings: list[Finding]) -> int:
        return sum(1 for f in findings if self.add(f))

    def sorted(self) -> list[Finding]:
        return sorted(self._items.values(), key=lambda f: (-f.severity.rank, f.asset, f.check_id))

    def by_severity(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for finding in self.sorted():
            out.setdefault(finding.severity.value, []).append(finding)
        return out

    def group_by_cwe(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for finding in self.sorted():
            out.setdefault(finding.group_key, []).append(finding)
        return out

    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self._items.values():
            counts[finding.severity.value] += 1
        return counts

    def to_list(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self.sorted()]


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _stable_path(url: str) -> str:
    if not url:
        return ""
    parts = urlsplit(url)
    path = re.sub(r"/{2,}", "/", parts.path) or "/"
    return f"{parts.netloc.lower()}{path}"


def _norm_cwe(value: str) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    return f"CWE-{digits}" if digits else ""
