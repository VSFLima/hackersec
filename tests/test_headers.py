import pytest

from hs.checks.headers import (
    HSTS_MIN_MAX_AGE,
    check_cors,
    check_cookies,
    check_csp_strength,
    check_hsts_strength,
    check_security_headers,
    check_version_disclosure,
    findings_from_exchange,
    parse_set_cookie,
)
from hs.core.http import Exchange
from hs.core.models import Severity

URL = "https://a.example.com/"
GOOD = {
    "Strict-Transport-Security": f"max-age={HSTS_MIN_MAX_AGE}; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}


def ids(findings):
    return {f.check_id for f in findings}


def by_id(findings, check_id):
    return next(f for f in findings if f.check_id == check_id)


class TestSecurityHeaders:
    def test_alvo_completo_nao_gera_finding(self):
        assert check_security_headers(GOOD, URL) == []

    def test_detecta_headers_ausentes(self):
        found = check_security_headers({}, URL)
        assert {"missing-hsts", "missing-csp", "missing-xcto", "missing-xfo", "missing-referrer-policy"} <= ids(found)

    def test_hsts_nao_e_exigido_em_http(self):
        found = check_security_headers({}, "http://a.example.com/")
        assert "missing-hsts" not in ids(found)

    def test_xfo_dispensado_com_frame_ancestors(self):
        headers = {k: v for k, v in GOOD.items() if k != "X-Frame-Options"}
        headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        assert "missing-xfo" not in ids(check_security_headers(headers, URL))

    def test_finding_preserva_asset_e_url(self):
        f = by_id(check_security_headers({}, URL), "missing-csp")
        assert f.asset == "a.example.com"
        assert f.url == URL
        assert f.severity is Severity.MEDIUM
        assert f.cwe == "CWE-693"
        assert f.remediation

    def test_evidence_aponta_header_ausente(self):
        f = by_id(check_security_headers({}, URL), "missing-csp")
        assert f.evidence["missing_header"] == "content-security-policy"

    def test_headers_case_insensitive(self):
        headers = {k.upper(): v for k, v in GOOD.items()}
        assert check_security_headers(headers, URL) == []

    def test_finding_tem_check_id_unico_por_header(self):
        found = check_security_headers({}, URL)
        assert len({f.check_id for f in found}) == len(found)


class TestHstsStrength:
    def test_aceita_politica_forte(self):
        strong = {"Strict-Transport-Security": f"max-age={HSTS_MIN_MAX_AGE}; includeSubDomains"}
        assert check_hsts_strength(strong, URL) == []

    def test_detecta_ausencia_de_subdominios(self):
        found = check_hsts_strength({"Strict-Transport-Security": f"max-age={HSTS_MIN_MAX_AGE}"}, URL)
        assert "hsts-no-subdomains" in ids(found)

    def test_detecta_max_age_curto(self):
        found = check_hsts_strength(
            {"Strict-Transport-Security": "max-age=100; includeSubDomains"}, URL
        )
        assert "hsts-short-max-age" in ids(found)
        assert by_id(found, "hsts-short-max-age").evidence["max_age"] == 100

    def test_aceita_max_age_no_limite(self):
        found = check_hsts_strength(
            {"Strict-Transport-Security": f"max-age={HSTS_MIN_MAX_AGE}; includeSubDomains"}, URL
        )
        assert found == []

    def test_sem_header_nao_gera_nada(self):
        assert check_hsts_strength({}, URL) == []

    def test_max_age_sem_numeros_e_ignorado(self):
        found = check_hsts_strength({"Strict-Transport-Security": "includeSubDomains"}, URL)
        assert "hsts-short-max-age" not in ids(found)


class TestCspStrength:
    def test_detecta_unsafe_inline(self):
        found = check_csp_strength({"Content-Security-Policy": "script-src 'unsafe-inline'"}, URL)
        assert "csp-unsafe-directive" in ids(found)
        assert "unsafe-inline" in by_id(found, "csp-unsafe-directive").evidence["directives"]

    def test_detecta_unsafe_eval(self):
        assert "csp-unsafe-directive" in ids(
            check_csp_strength({"Content-Security-Policy": "script-src 'unsafe-eval'"}, URL)
        )

    def test_csp_forte_passa(self):
        assert check_csp_strength({"Content-Security-Policy": "default-src 'self'"}, URL) == []

    def test_sem_csp_nao_gera_nada(self):
        assert check_csp_strength({}, URL) == []


class TestVersionDisclosure:
    @pytest.mark.parametrize("header", ["Server", "X-Powered-By", "X-AspNet-Version"])
    def test_detecta_versao(self, header):
        found = check_version_disclosure({header: "9.9.9"}, URL)
        assert "version-disclosure" in ids(found)

    def test_ignora_valor_sem_versao(self):
        assert check_version_disclosure({"Server": "nginx"}, URL) == []

    def test_guarda_valor_como_evidencia(self):
        found = check_version_disclosure({"X-Powered-By": "PHP/8.1.2"}, URL)
        assert by_id(found, "version-disclosure").evidence["value"] == "PHP/8.1.2"


class TestCookies:
    def test_parse_set_cookie_completo(self):
        parsed = parse_set_cookie("sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict")
        assert parsed["name"] == "sid"
        assert parsed["secure"] and parsed["httponly"]
        assert parsed["samesite"] == "SameSite=Strict"

    def test_parse_set_cookie_minimo(self):
        parsed = parse_set_cookie("sid=abc123")
        assert parsed["name"] == "sid" and not parsed["secure"]

    def test_detecta_cookie_sem_flags(self):
        found = check_cookies({"Set-Cookie": ["sid=abc"]}, URL)
        f = by_id(found, "cookie-missing-flags")
        assert set(f.evidence["flags_missing"]) == {"sem Secure", "sem HttpOnly", "sem SameSite"}
        assert f.severity is Severity.MEDIUM

    def test_cookie_completo_passa(self):
        headers = {"Set-Cookie": ["sid=abc; Secure; HttpOnly; SameSite=Lax"]}
        assert check_cookies(headers, URL) == []

    def test_aceita_string_unica(self):
        assert check_cookies({"Set-Cookie": "sid=abc; Secure; HttpOnly; SameSite=Lax"}, URL) == []

    def test_aceita_multiplos_cookies(self):
        headers = {"Set-Cookie": ["a=1", "b=2; Secure; HttpOnly; SameSite=Lax"]}
        found = check_cookies(headers, URL)
        assert len(found) == 1 and by_id(found, "cookie-missing-flags").evidence["cookie"] == "a"

    def test_severidade_baixa_quando_so_falta_samesite(self):
        found = check_cookies({"Set-Cookie": ["sid=abc; Secure; HttpOnly"]}, URL)
        assert by_id(found, "cookie-missing-flags").severity is Severity.LOW

    def test_severidade_sobe_sem_httponly(self):
        found = check_cookies({"Set-Cookie": ["sid=abc; Secure; SameSite=Lax"]}, URL)
        assert by_id(found, "cookie-missing-flags").severity is Severity.MEDIUM

    def test_cookie_malformado_e_ignorado(self):
        assert check_cookies({"Set-Cookie": ["lixo"]}, URL) == []


class TestCors:
    def test_wildcard_com_credenciais_e_high(self):
        found = check_cors(
            "https://evil.example",
            {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
            URL,
            request_credentials=True,
        )
        f = by_id(found, "cors-wildcard-credentials")
        assert f.severity is Severity.HIGH and f.cwe == "CWE-942"

    def test_wildcard_sem_credenciais_passa(self):
        assert (
            check_cors("https://evil.example", {"Access-Control-Allow-Origin": "*"}, URL) == []
        )

    def test_reflexao_de_origem_com_credenciais(self):
        found = check_cors(
            "https://evil.example",
            {"Access-Control-Allow-Origin": "https://evil.example", "Access-Control-Allow-Credentials": "true"},
            URL,
            request_credentials=True,
        )
        assert "cors-origin-reflection-credentials" in ids(found)

    def test_reflexao_de_origem_sem_credenciais_passa(self):
        assert (
            check_cors(
                "https://evil.example",
                {"Access-Control-Allow-Origin": "https://evil.example"},
                URL,
            )
            == []
        )

    def test_origem_confiavel_nao_e_finding(self):
        found = check_cors(
            "https://app.example.com",
            {"Access-Control-Allow-Origin": "https://app.example.com", "Access-Control-Allow-Credentials": "true"},
            URL,
            request_credentials=True,
            trusted_origins=["https://app.example.com/"],
        )
        assert found == []

    def test_origem_nao_confiavel_refletida_e_finding(self):
        found = check_cors(
            "https://evil.example",
            {"Access-Control-Allow-Origin": "https://evil.example", "Access-Control-Allow-Credentials": "true"},
            URL,
            request_credentials=True,
            trusted_origins=["https://app.example.com"],
        )
        assert "cors-origin-reflection-credentials" in ids(found)

    def test_sem_cors_nao_gera_nada(self):
        assert check_cors("https://evil.example", {}, URL) == []


class TestFindingsFromExchange:
    def _exchange(self, **kw):
        base = dict(url=URL, status=200, response_headers=dict(GOOD), body_preview="")
        base.update(kw)
        return Exchange(**base)

    def test_exchange_saudavel_nao_gera_findings(self):
        assert findings_from_exchange(self._exchange()) == []

    def test_erro_de_rede_nao_gerou_header_findings(self):
        ex = self._exchange(status=None, error="ConnectionError", response_headers={})
        assert findings_from_exchange(ex) == []

    def test_ACHou_headers_ausentes(self):
        ex = self._exchange(response_headers={})
        assert "missing-csp" in ids(findings_from_exchange(ex))

    def test_ACHou_cors_wildcard(self):
        ex = self._exchange(
            response_headers={**GOOD, "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
        )
        found = findings_from_exchange(ex)
        assert "cors-wildcard-credentials" in ids(found) or "cors-origin-reflection-credentials" in ids(found)

    def test_checks_externos_sao_incluidos(self):
        sentinel: list = []
        found = findings_from_exchange(self._exchange(), extra_checks=sentinel)
        assert found == sentinel
