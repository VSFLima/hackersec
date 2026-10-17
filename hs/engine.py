"""Orquestrador: junta recon, probe, superficie web e segredos num unico run.

Cada fase e isolada e testavel isoladamente. A ordem segue o principio
"passivo primeiro, ativo depois": logs de certificado nao tocam no alvo,
o probe e a superficie web sim.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .checks.headers import findings_from_exchange
from .checks.secrets import extract_js_endpoints, scan_path, scan_secrets, to_findings
from .core.http import Exchange, SafeClient
from .core.models import Asset, Finding, FindingSet, Severity
from .core.scope import Scope, ScopeError
from .recon.ct import enumerate_ct, merge_hosts
from .recon.probe import probe_all

_JS_SRC_RE = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']""",
    re.IGNORECASE,
)
_JS_HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']""", re.IGNORECASE)


@dataclass
class RunResult:
    program: str = ""
    assets: list[Asset] = field(default_factory=list)
    findings: FindingSet = field(default_factory=FindingSet)
    exchanges: list[Exchange] = field(default_factory=list)
    blocked: list[Exchange] = field(default_factory=list)
    duration_s: float = 0.0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "program": self.program,
            "assets": [a.to_dict() for a in self.assets],
            "findings": self.findings.to_list(),
            "duration_s": round(self.duration_s, 2),
            "counts": self.findings.counts(),
            "blocked_requests": len(self.blocked),
            "notes": self.notes,
        }


class Engine:
    def __init__(self, scope: Scope, *, client: SafeClient | None = None, **client_kwargs: Any) -> None:
        self.scope = scope
        self._owns_client = client is None
        self.client = client or SafeClient(scope, **client_kwargs)

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def __enter__(self) -> "Engine":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ recon

    def discover_hosts(self, seeds: Sequence[str], *, use_ct: bool = True) -> list[str]:
        """Fase passiva:certificate transparency + seeds, tudo filtrado pelo scope."""
        found: list[str] = []
        authorized_seeds = [s for s in seeds if self.scope.is_allowed(s)]
        found.extend(authorized_seeds)
        if use_ct:
            for seed in authorized_seeds:
                result = enumerate_ct(seed, self.client, self.scope)
                found.extend(result.hosts)
        return merge_hosts(found)

    def run_recon(
        self,
        seeds: Sequence[str],
        *,
        use_ct: bool = True,
        do_probe: bool = True,
        do_surface: bool = True,
        workers: int = 10,
    ) -> RunResult:
        started = time.monotonic()
        result = RunResult(program=self.scope.program)
        if not seeds:
            result.notes.append("nenhuma seed fornecida")
            return result

        hosts = self.discover_hosts(seeds, use_ct=use_ct)
        if not hosts:
            result.notes.append("nenhum host autorizado encontrado")
            result.duration_s = time.monotonic() - started
            return result

        if not do_probe:
            result.assets = [Asset(host=h, sources=["seed"]) for h in hosts]
            result.duration_s = time.monotonic() - started
            return result

        live = probe_all(self.client, hosts, workers=workers)
        result.assets = live

        if do_surface:
            for asset in live:
                if not asset.status or asset.status >= 500:
                    continue
                result.findings.extend(self._audit_asset(asset))
                result.findings.extend(self._scan_asset_js(asset))

        result.exchanges = list(self.client.exchanges)
        result.blocked = list(self.client.blocked)
        result.duration_s = time.monotonic() - started
        if self.scope.bypass:
            result.notes.append(
                "SCOPE DESLIGADO: os alvos nao foram validados contra um escopo autorizado"
            )
        return result

    # ---------------------------------------------------------------- surface

    def audit_url(self, url: str) -> list[Finding]:
        """Audita uma unica URL (headers, cookies, CORS)."""
        response = self.client.try_get(url)
        if response is None:
            return []
        return self._findings_for_exchange(self.client.exchanges[-1])

    def audit_asset(self, asset: Asset) -> list[Finding]:
        return self._audit_asset(asset)

    def _audit_asset(self, asset: Asset) -> list[Finding]:
        url = asset.url or f"http://{asset.host}"
        response = self.client.try_get(url)
        if response is None:
            return []
        return self._findings_for_exchange(self.client.exchanges[-1])

    def _findings_for_exchange(self, exchange: Exchange) -> list[Finding]:
        return findings_from_exchange(exchange)

    def _scan_asset_js(self, asset: Asset) -> list[Finding]:
        """Descarrega os JS referenciados pela pagina e procura segredos neles."""
        findings: list[Finding] = []
        base = asset.url or f"http://{asset.host}"
        exchange = next(
            (e for e in reversed(self.client.exchanges) if e.url == base and e.body_preview), None
        )
        if exchange is None:
            return findings
        for src in self._js_urls(exchange.body_preview, base):
            if not self.scope.is_allowed(src):
                continue
            js_exchange = self._fetch_body(src)
            if js_exchange is None:
                continue
            for found in scan_secrets(js_exchange.body_preview, source=src):
                findings.append(found.to_finding(asset=asset.host))
        return findings

    def _js_urls(self, body: str, base: str) -> list[str]:
        from urllib.parse import urljoin

        urls: dict[str, None] = {}
        for match in list(_JS_SRC_RE.finditer(body or "")) + list(_JS_HREF_RE.finditer(body or "")):
            urls.setdefault(urljoin(base, match.group(1)), None)
        return list(urls)

    def _fetch_body(self, url: str) -> Exchange | None:
        before = len(self.client.exchanges)
        self.client.try_get(url)
        if len(self.client.exchanges) == before:
            return None
        return self.client.exchanges[-1]

    def endpoints_in_js(self, body: str) -> list[str]:
        return extract_js_endpoints(body)

    # ---------------------------------------------------------------- secrets

    def scan_source(self, path: str, *, allow_generic: bool = True) -> list[Finding]:
        return to_findings(scan_path(path, allow_generic=allow_generic))

    def scan_text(self, text: str, *, source: str = "conteudo") -> list[Finding]:
        return to_findings(scan_secrets(text, source=source))

    # ------------------------------------------------------------------ misc

def load_scope(path: str, *, bypass: bool = False) -> Scope:
    try:
        return Scope.from_file(path, bypass=bypass)
    except ScopeError:
        raise


def severity_breakdown(findings: FindingSet) -> dict[str, int]:
    return {k: v for k, v in findings.counts().items() if v}


def actionable(findings: Iterable[Finding], minimum: Severity = Severity.MEDIUM) -> list[Finding]:
    return sorted(
        (f for f in findings if f.severity.rank >= minimum.rank),
        key=lambda f: -f.severity.rank,
    )
