"""Recon passivo via Certificate Transparency (crt.sh).

Nenhum trafego e enviado ao alvo: a coleta vem de logs publicos de emissao
de certificados. Todo resultado passa pelo scope antes de virar Asset.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from ..core.http import SafeClient
from ..core.models import Asset
from ..core.scope import Scope

CRTSH_URL = "https://crt.sh/"

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_UNDERSCORE_RE = re.compile(r"^_")
_DEDUP_NOISE = frozenset({"localhost"})


@dataclass
class CTResult:
    hosts: list[str]
    raw_entries: int
    filtered_out: int

    def as_assets(self, scope: Scope, source: str = "crt.sh") -> list[Asset]:
        return [
            Asset(host=host, sources=[source])
            for host in self.hosts
            if scope.is_allowed(host)
        ]


def is_valid_hostname(host: str) -> bool:
    text = (host or "").strip().lower().rstrip(".")
    if not text or _UNDERSCORE_RE.match(text) or text in _DEDUP_NOISE:
        return False
    if "*" in text or len(text) > 253:
        return False
    return bool(_HOST_RE.match(text))


def in_root_domain(host: str, root: str) -> bool:
    """True se `host` e o dominio-raiz ou um subdominio dele."""
    host = (host or "").strip().lower().rstrip(".")
    root = (root or "").strip().lower().lstrip(".").rstrip(".")
    if not host or not root:
        return False
    return host == root or host.endswith(f".{root}")


def parse_crtsh(payload: str | Iterable[dict[str, Any]], root: str | None = None) -> CTResult:
    """Extrai hostnames unicos de uma resposta do crt.sh.

    Com `root`, descarta tudo que nao pertenca ao dominio-raiz pesquisado.
    """
    import json

    if isinstance(payload, str):
        text = payload.strip()
        entries: list[dict[str, Any]] = json.loads(text) if text else []
    else:
        entries = list(payload)

    seen: dict[str, None] = {}
    raw_count = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            value = entry.get(field) or ""
            for candidate in str(value).replace(",", "\n").splitlines():
                raw_count += 1
                host = candidate.strip().lower().rstrip(".")
                if host.startswith("*."):
                    host = host[2:]
                if not is_valid_hostname(host):
                    continue
                if root and not in_root_domain(host, root):
                    continue
                seen.setdefault(host, None)

    hosts = sorted(seen)
    return CTResult(hosts=hosts, raw_entries=raw_count, filtered_out=raw_count - len(hosts))


def enumerate_ct(
    domain: str,
    client: SafeClient,
    scope: Scope,
    *,
    exclude_expired: bool = True,
) -> CTResult:
    """Consulta o crt.sh para `domain` e devolve apenas hosts autorizados."""
    domain = domain.strip().lower().lstrip(".")
    if not scope.is_allowed(domain):
        return CTResult(hosts=[], raw_entries=0, filtered_out=0)

    params = {"q": f"%.{domain}", "output": "json"}
    if exclude_expired:
        params["exclude"] = "expired"

    response = client.try_get(CRTSH_URL, params=params)
    if response is None or response.status_code != 200:
        return CTResult(hosts=[], raw_entries=0, filtered_out=0)

    try:
        result = parse_crtsh(response.text, root=domain)
    except ValueError:
        return CTResult(hosts=[], raw_entries=0, filtered_out=0)

    allowed = [h for h in result.hosts if scope.is_allowed(h)]
    return CTResult(
        hosts=sorted(allowed),
        raw_entries=result.raw_entries,
        filtered_out=(result.raw_entries - len(result.hosts)) + (len(result.hosts) - len(allowed)),
    )


def merge_hosts(*groups: Iterable[str]) -> list[str]:
    """Une varias fontes de host, removendo duplicados e wildcards."""
    seen: dict[str, None] = {}
    for group in groups:
        for raw in group or []:
            host = (raw or "").strip().lower().rstrip(".")
            if host.startswith("*."):
                host = host[2:]
            if is_valid_hostname(host):
                seen.setdefault(host, None)
    return sorted(seen)
