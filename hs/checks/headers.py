"""Checks de superficie web: headers de seguranca, cookies, CORS, TLS.

Funcoes puras: recebem headers/texto/certificado e devolvem `Finding`.
Nao fazem rede, o que as torna testaveis de forma exhaustiva.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from ..core.http import Exchange
from ..core.models import Finding, Severity

HSTS_MIN_MAX_AGE = 15_552_000
INSECURE_CSP_DIRECTIVES = ("unsafe-inline", "unsafe-eval")
VERSION_RE = re.compile(r"\d+\.\d+")
HSTS_RE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)
SET_COOKIE_RE = re.compile(r"^\s*([^=;]+)=([^;]*)", re.IGNORECASE)

SECURITY_HEADERS: dict[str, tuple[str, str, str, str]] = {
    "strict-transport-security": (
        "missing-hsts",
        "Falta Strict-Transport-Security",
        Severity.MEDIUM,
        "CWE-319",
    ),
    "content-security-policy": (
        "missing-csp",
        "Falta Content-Security-Policy",
        Severity.MEDIUM,
        "CWE-693",
    ),
    "x-content-type-options": (
        "missing-xcto",
        "Falta X-Content-Type-Options",
        Severity.LOW,
        "CWE-16",
    ),
    "x-frame-options": (
        "missing-xfo",
        "Falta protecao contra clickjacking (X-Frame-Options)",
        Severity.LOW,
        "CWE-1021",
    ),
    "referrer-policy": (
        "missing-referrer-policy",
        "Falta Referrer-Policy",
        Severity.LOW,
        "CWE-200",
    ),
    "permissions-policy": (
        "missing-permissions-policy",
        "Falta Permissions-Policy",
        Severity.INFO,
        "CWE-693",
    ),
}

_FRAMING_CSP = re.compile(r"frame-ancestors", re.IGNORECASE)


def _f(
    check_id: str,
    title: str,
    severity: Severity,
    cwe: str,
    description: str,
    remediation: str,
    **kw: Any,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        cwe=cwe,
        description=description,
        remediation=remediation,
        **kw,
    )


def check_security_headers(
    headers: Mapping[str, str],
    url: str,
    *,
    body: str = "",
) -> list[Finding]:
    lower = {k.lower(): v for k, v in headers.items()}
    host = urlsplit(url).hostname or url
    is_https = urlsplit(url).scheme == "https"
    findings: list[Finding] = []

    for header, (check_id, title, severity, cwe) in SECURITY_HEADERS.items():
        if lower.get(header):
            continue
        if check_id == "missing-hsts" and not is_https:
            continue
        if check_id == "missing-xfo" and _FRAMING_CSP.search(lower.get("content-security-policy", "")):
            continue
        findings.append(
            _f(
                check_id,
                title,
                severity,
                cwe,
                f"A resposta de {url} nao define o header '{header}'.",
                f"Defina o header '{header}' appropriate para a aplicacao.",
                asset=host,
                url=url,
                evidence={"missing_header": header},
            )
        )

    findings.extend(check_hsts_strength(headers, url))
    findings.extend(check_csp_strength(headers, url))
    findings.extend(check_version_disclosure(headers, url))
    findings.extend(check_cookies(headers, url))
    return findings


def check_hsts_strength(headers: Mapping[str, str], url: str) -> list[Finding]:
    value = _lower(headers).get("strict-transport-security", "")
    if not value:
        return []
    if "includesubdomains" not in value.lower():
        return [
            _f(
                "hsts-no-subdomains",
                "HSTS sem includeSubDomains",
                Severity.LOW,
                "CWE-319",
                f"A politica HSTS de {url} nao cobre subdominios.",
                "Adicione 'includeSubDomains' a diretiva.",
                asset=_host(url),
                url=url,
                evidence={"header": value},
            )
        ]
    match = HSTS_RE.search(value)
    if not match:
        return []
    if int(match.group(1)) < HSTS_MIN_MAX_AGE:
        return [
            _f(
                "hsts-short-max-age",
                "HSTS com max-age curto",
                Severity.LOW,
                "CWE-319",
                f"max-age={match.group(1)} esta abaixo do recomendado ({HSTS_MIN_MAX_AGE}).",
                f"Use max-age no minimo {HSTS_MIN_MAX_AGE}.",
                asset=_host(url),
                url=url,
                evidence={"max_age": int(match.group(1))},
            )
        ]
    return []


def check_csp_strength(headers: Mapping[str, str], url: str) -> list[Finding]:
    value = _lower(headers).get("content-security-policy", "")
    if not value:
        return []
    found = [d for d in INSECURE_CSP_DIRECTIVES if d in value.lower()]
    if not found:
        return []
    return [
        _f(
            "csp-unsafe-directive",
            f"CSP com {', '.join(found)}",
            Severity.LOW,
            "CWE-1021",
            f"A CSP de {url} permite execucao inline/eval, reduzindo a protecao contra XSS.",
            "Remova 'unsafe-inline' e 'unsafe-eval'; use nonces ou hashes.",
            asset=_host(url),
            url=url,
            evidence={"directives": found},
        )
    ]


def check_version_disclosure(headers: Mapping[str, str], url: str) -> list[Finding]:
    lower = _lower(headers)
    findings: list[Finding] = []
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = lower.get(header, "")
        if value and VERSION_RE.search(value):
            findings.append(
                _f(
                    "version-disclosure",
                    f"Header {header} expoe versao ({value})",
                    Severity.LOW,
                    "CWE-200",
                    f"O header '{header}' revela detalhes da stack: {value!r}.",
                    "Remova ou generalize o header para nao expor versoes exatas.",
                    asset=_host(url),
                    url=url,
                    evidence={"header": header, "value": value},
                )
            )
    return findings


def parse_set_cookie(raw: str) -> dict[str, str]:
    match = SET_COOKIE_RE.match(raw or "")
    if not match:
        return {}
    name, value = match.group(1).strip(), match.group(2).strip()
    parts = [p.strip() for p in (raw or "").split(";")[1:]]
    flags = {p.split("=", 1)[0].strip().lower() for p in parts if p}
    return {
        "name": name,
        "value": value,
        "secure": "secure" in flags,
        "httponly": "httponly" in flags,
        "samesite": next((p for p in parts if p.lower().startswith("samesite")), ""),
        "raw": raw,
    }


def check_cookies(headers: Mapping[str, str], url: str, *, is_https: bool = True) -> list[Finding]:
    cookies = headers.get("Set-Cookie") or []
    if isinstance(cookies, str):
        cookies = [cookies]
    findings: list[Finding] = []
    for raw in cookies:
        parsed = parse_set_cookie(raw)
        if not parsed.get("name"):
            continue
        problems: list[str] = []
        if is_https and not parsed["secure"]:
            problems.append("sem Secure")
        if not parsed["httponly"]:
            problems.append("sem HttpOnly")
        if not parsed["samesite"]:
            problems.append("sem SameSite")
        if not problems:
            continue
        high_impact = "sem Secure" in problems or "sem HttpOnly" in problems
        findings.append(
            _f(
                "cookie-missing-flags",
                f"Cookie '{parsed['name']}' {', '.join(problems)}",
                Severity.MEDIUM if high_impact else Severity.LOW,
                "CWE-614" if "sem Secure" in problems else "CWE-1004",
                f"O cookie '{parsed['name']}' de {url} {', '.join(problems)}.",
                "Adicione as diretivas Secure, HttpOnly e SameSite ao cookie.",
                asset=_host(url),
                url=url,
                evidence={"cookie": parsed["name"], "flags_missing": problems, "raw": raw},
            )
        )
    return findings


def check_cors(
    request_origin: str,
    headers: Mapping[str, str],
    url: str,
    *,
    request_credentials: bool = False,
    trusted_origins: Iterable[str] = (),
) -> list[Finding]:
    lower = _lower(headers)
    allow_origin = lower.get("access-control-allow-origin", "")
    allow_credentials = lower.get("access-control-allow-credentials", "").strip().lower() == "true"
    if not allow_origin:
        return []

    credentials = allow_credentials or request_credentials
    if not credentials:
        return []

    evidence = {
        "access_control_allow_origin": allow_origin,
        "access_control_allow_credentials": allow_credentials,
        "origin_testado": request_origin,
    }

    if allow_origin == "*":
        return [
            _f(
                "cors-wildcard-credentials",
                "CORS com wildcard e credenciais",
                Severity.HIGH,
                "CWE-942",
                f"{url} aceita '*' em Access-Control-Allow-Origin junto com credenciais.",
                "Nunca combine wildcard com Access-Control-Allow-Credentials: true.",
                asset=_host(url),
                url=url,
                evidence=evidence,
            )
        ]

    if request_origin and allow_origin == request_origin:
        trusted = {o.strip().lower().rstrip("/") for o in trusted_origins}
        if request_origin.strip().lower().rstrip("/") in trusted:
            return []
        return [
            _f(
                "cors-origin-reflection-credentials",
                "CORS reflete origem arbitraria com credenciais",
                Severity.HIGH,
                "CWE-942",
                f"{url} ecoa a origem testada em Access-Control-Allow-Origin e permite credenciais.",
                "Use uma lista explicita de origens permitidas.",
                asset=_host(url),
                url=url,
                evidence=evidence,
            )
        ]
    return []


def check_open_redirect_probe(exchange: Exchange, param: str) -> Finding | None:
    """Confirma open redirect comparando o Location resultante."""
    location = exchange.response_headers.get("Location", "")
    if exchange.status not in (301, 302, 303, 307, 308) or not location:
        return None
    if not location.lower().startswith(("http://", "https://", "//")):
        return None
    return _f(
        "open-redirect",
        f"Open redirect via {param}",
        Severity.MEDIUM,
        "CWE-601",
        f"O parametro '{param}' levou a um redirecionamento para um destino externo.",
        "Restrinja o valor aceito ou valide o destino contra uma allowlist.",
        asset=_host(exchange.url),
        url=exchange.url,
        evidence={"param": param, "location": location, "status": exchange.status},
    )


def findings_from_exchange(
    exchange: Exchange,
    *,
    extra_checks: Iterable[Any] = (),
) -> list[Finding]:
    """Roda o conjunto padrao de checks sobre um Exchange capturado."""
    findings = list(extra_checks)
    if exchange.error or exchange.status is None:
        return findings
    url = exchange.url
    findings.extend(check_security_headers(exchange.response_headers, url, body=exchange.body_preview))
    findings.extend(check_cors("https://evil.example", exchange.response_headers, url))
    return findings


def _lower(headers: Mapping[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def _host(url: str) -> str:
    return urlsplit(url).hostname or url
