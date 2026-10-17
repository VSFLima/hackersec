"""Scope engine: allowlist bloqueante para testes autorizados.

Deny-by-default. Um alvo so e considerado autorizado se casar explicitamente
com uma regra de `include`. Regras de `exclude` tem precedencia sobre include.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


class ScopeError(Exception):
    """Erro de configuracao ou de uso do scope."""


DEFAULT_PORTS = frozenset({80, 443, 8080, 8443, 8000, 3000, 5000})

DEFAULT_DENY_EXTENSIONS = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".css", ".mp4", ".zip"}
)

_PORT_SUFFIX = re.compile(r"^(?P<host>.+):(?P<port>\d+)$")


def _normalize_host(raw: str) -> str:
    host = raw.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if host.startswith("http://"):
        host = host[7:]
    elif host.startswith("https://"):
        host = host[8:]
    if "/" in host:
        host = host.split("/", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _split_port(raw: str) -> tuple[str, int | None]:
    match = _PORT_SUFFIX.match(raw.strip())
    if not match:
        return _normalize_host(raw), None
    candidate = match.group("host")
    if candidate.count(":") >= 1 and not candidate.startswith("["):
        return _normalize_host(raw), None
    return _normalize_host(candidate), int(match.group("port"))


@dataclass(frozen=True)
class Rule:
    """Regra de escopo ja decomposta."""

    raw: str
    host: str
    port: int | None
    wildcard: bool
    network: Any = None

    def matches(self, host: str, port: int | None) -> bool:
        if self.port is not None and port is not None and self.port != port:
            return False
        if self.network is not None:
            try:
                return ipaddress.ip_address(host) in self.network
            except ValueError:
                return False
        if self.wildcard:
            return host == self.host or host.endswith(f".{self.host}")
        return host == self.host


def _parse_rule(raw: str) -> Rule:
    text = raw.strip()
    if text.startswith("*."):
        return Rule(raw=raw, host=_normalize_host(text[2:]), port=None, wildcard=True)
    base, port = _split_port(text)
    if port is None and "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            network = None
        if network is not None:
            return Rule(raw=raw, host=text, port=None, wildcard=False, network=network)
    return Rule(raw=raw, host=base, port=port, wildcard=False)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class Decision:
    """Resultado de uma consulta de escopo."""

    allowed: bool
    host: str
    port: int | None = None
    reason: str = ""
    matched_rule: str = ""

    def __bool__(self) -> bool:
        return self.allowed


@dataclass
class Scope:
    """Allowlist de alvos autorizados.

    Modo normal: so hosts dentro de `include` passam.
    Modo desligado (`bypass=True`): tudo passa, mas cada decisao carrega um
    aviso explicito no campo `reason` para nao ser silenciosa.
    """

    program: str = "unnamed-program"
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    allowed_ports: frozenset[int] = frozenset(DEFAULT_PORTS)
    deny_extensions: frozenset[str] = frozenset(DEFAULT_DENY_EXTENSIONS)
    authorized_by: str = ""
    authorization_ref: str = ""
    bypass: bool = False

    _include_rules: list[Rule] = field(default_factory=list, repr=False)
    _exclude_rules: list[Rule] = field(default_factory=list, repr=False)

    # ------------------------------------------------------------------ load

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, bypass: bool = False) -> "Scope":
        if not isinstance(data, dict):
            raise ScopeError("scope deve ser um mapeamento YAML")

        auth = data.get("authorization") or {}
        if not isinstance(auth, dict):
            raise ScopeError("authorization deve ser um mapeamento")

        scope = cls(
            program=str(data.get("program", "unnamed-program")),
            include=_as_str_list(data.get("include"), "include"),
            exclude=_as_str_list(data.get("exclude"), "exclude"),
            allowed_ports=frozenset(_as_int_list(data.get("allowed_ports"), "allowed_ports")) or frozenset(DEFAULT_PORTS),
            deny_extensions=frozenset(
                e.lower() if e.startswith(".") else f".{e.lower()}"
                for e in _as_str_list(data.get("deny_extensions"), "deny_extensions")
            )
            or frozenset(DEFAULT_DENY_EXTENSIONS),
            authorized_by=str(auth.get("authorized_by", "")).strip(),
            authorization_ref=str(auth.get("reference", "")).strip(),
            bypass=bypass,
        )
        scope._compile()
        return scope

    @classmethod
    def from_file(cls, path: str | Path, *, bypass: bool = False) -> "Scope":
        p = Path(path)
        if not p.is_file():
            raise ScopeError(f"scope nao encontrado: {p}")
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ScopeError(f"scope invalido: {exc}") from exc
        return cls.from_dict(data or {}, bypass=bypass)

    def _compile(self) -> None:
        self._include_rules = [_parse_rule(r) for r in self.include]
        self._exclude_rules = [_parse_rule(r) for r in self.exclude]
        if self.bypass:
            return
        if not self.include:
            raise ScopeError("scope sem 'include': nada seria autorizado (deny-by-default)")
        if not self.authorized_by:
            raise ScopeError("scope sem 'authorization.authorized_by': sao obrigatorios nome e referencia da autorizacao")

    # ----------------------------------------------------------------- query

    def check(self, target: str, *, port: int | None = None) -> Decision:
        """Decide se `target` (host, host:port ou URL) pode ser testado."""
        raw = (target or "").strip()
        if not raw:
            return Decision(False, "", reason="alvo vazio")

        embedded_port = None
        path = ""
        if "://" in raw:
            parts = urlsplit(raw)
            raw = parts.netloc
            path = parts.path or ""
            if parts.port:
                embedded_port = parts.port
        elif "/" in raw:
            head, _, tail = raw.partition("/")
            raw, path = head, tail

        host, suffix_port = _split_port(raw)
        port = port or suffix_port or embedded_port
        host = _normalize_host(host)

        if not host:
            return Decision(False, raw, port, reason="host nao extraido do alvo")

        if self.bypass:
            return Decision(
                True, host, port, reason="SCOPE DESLIGADO: alvo NAO VERIFICADO contra o escopo autorizado"
            )

        if not self.authorized_by:
            return Decision(False, host, port, reason="scope sem autorizacao registrada")

        ext = _extension(path)
        if ext and ext in self.deny_extensions:
            return Decision(False, host, port, reason=f"extensao negada: {ext}")

        if port is not None and self.allowed_ports and port not in self.allowed_ports:
            return Decision(False, host, port, reason=f"porta {port} fora de allowed_ports")

        excluded = self._match(self._exclude_rules, host, port)
        if excluded:
            return Decision(False, host, port, reason="casou com exclude", matched_rule=excluded)

        if not self.include:
            return Decision(False, host, port, reason="scope sem include: deny-by-default")

        matched = self._match(self._include_rules, host, port)
        if not matched:
            return Decision(False, host, port, reason="fora do escopo autorizado")

        return Decision(True, host, port, reason="dentro do escopo autorizado", matched_rule=matched)

    def is_allowed(self, target: str, *, port: int | None = None) -> bool:
        return self.check(target, port=port).allowed

    def filter(self, targets: list[str]) -> tuple[list[str], list[Decision]]:
        """Particiona uma lista de alvos em (autorizados, bloqueados)."""
        allowed: list[str] = []
        denied: list[Decision] = []
        for target in targets:
            decision = self.check(target)
            (allowed.append(target) if decision.allowed else denied.append(decision))
        return allowed, denied

    def _match(self, rules: list[Rule], host: str, port: int | None) -> str:
        for rule in rules:
            if rule.matches(host, port):
                return rule.raw
        return ""


# ----------------------------------------------------------------- helpers


def _as_str_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise ScopeError(f"'{field_name}' deve ser uma lista")
    out = []
    for item in value:
        if not isinstance(item, (str, int)):
            raise ScopeError(f"'{field_name}' aceita apenas strings/numeros")
        text = str(item).strip()
        if text:
            out.append(text)
    return out


def _as_int_list(value: Any, field_name: str) -> list[int]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise ScopeError(f"'{field_name}' deve ser uma lista")
    out = []
    for item in value:
        try:
            out.append(int(item))
        except (TypeError, ValueError) as exc:
            raise ScopeError(f"'{field_name}' aceita apenas portas numericas") from exc
    return out


def _extension(path: str) -> str:
    if not path or path.endswith("/"):
        return ""
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return f".{name.rsplit('.', 1)[-1].lower()}"
