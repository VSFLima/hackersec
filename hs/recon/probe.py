"""Probe de hosts vivos: descobre esquema, status, titulo e stack."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

from ..core.http import SafeClient
from ..core.models import Asset

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_META_REFRESH_RE = re.compile(rb"""http-equiv=["']?refresh["']?""", re.IGNORECASE)

_TECH_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("nginx", ("nginx",)),
    ("apache", ("apache",)),
    ("iis", ("microsoft-iis", "asp.net")),
    ("cloudflare", ("cloudflare",)),
    ("akamai", ("akamaighost",)),
    ("fastly", ("fastly",)),
    ("vercel", ("vercel",)),
    ("netlify", ("netlify",)),
    ("amazon cloudfront", ("cloudfront",)),
    ("aws s3", ("amazons3", "amazon s3")),
    ("php", ("php", "x-powered-by: php")),
    ("nodejs", ("express", "x-powered-by: express")),
    ("django", ("csrfmiddlewaretoken", "django")),
    ("rails", ("x-runtime:", "_rails")),
    ("spring", ("whitelabel error page", "jsessionid")),
    ("graphql", ("graphql",)),
    ("wordpress", ("wp-content", "wp-includes")),
    ("drupal", ("drupal", "x-generator: drupal")),
    ("react", ("__next_data__", "data-reactroot", "/_next/")),
    ("vue", ("__vue__", "data-v-")),
    ("angular", ("ng-version", "app-root")),
)

DEFAULT_SCHEMES = ("https", "http")


def extract_title(body: str) -> str:
    match = _TITLE_RE.search(body or "")
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:300]


def detect_tech(headers: dict[str, str], body: str) -> list[str]:
    haystack_headers = " ".join(f"{k.lower()}: {v}" for k, v in headers.items()).lower()
    haystack_body = (body or "")[:200_000].lower()
    found: list[str] = []
    for tech, signatures in _TECH_SIGNATURES:
        for signature in signatures:
            if signature in haystack_headers or signature in haystack_body:
                found.append(tech)
                break
    return sorted(set(found))


def probe_host(
    client: SafeClient,
    host: str,
    *,
    schemes: Iterable[str] = DEFAULT_SCHEMES,
) -> Asset | None:
    """Tenta cada esquema e devolve o primeiro host que responder, ou None."""
    for scheme in schemes:
        url = f"{scheme}://{host}"
        response = client.try_get(url)
        if response is None:
            continue
        asset = Asset(
            host=host,
            url=str(response.url) or url,
            scheme=scheme,
            status=response.status_code,
            is_live=True,
            sources=["probe"],
        )
        asset.server = _header(response.headers, "Server")
        asset.title = extract_title(response.text or "")
        asset.tech = detect_tech(dict(response.headers), response.text or "")
        return asset
    return None


def _header(headers, name: str) -> str:
    try:
        return headers.get(name, "") or ""
    except AttributeError:
        return ""


def probe_all(
    client: SafeClient,
    hosts: Iterable[str],
    *,
    workers: int = 10,
    schemes: Iterable[str] = DEFAULT_SCHEMES,
) -> list[Asset]:
    """Faz probe paralelo e devolve apenas os hosts vivos."""
    unique = sorted({h.strip().lower().rstrip(".") for h in hosts if h and h.strip()})
    live: list[Asset] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(probe_host, client, host, schemes=schemes): host for host in unique}
        for future in as_completed(futures):
            asset = future.result()
            if asset is not None:
                live.append(asset)
    return sorted(live, key=lambda a: a.host)
