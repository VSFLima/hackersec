import json

import pytest
import requests
from requests.adapters import BaseAdapter
from requests.models import Response

from hs.core.http import SafeClient
from hs.core.models import Finding, Severity
from hs.core.scope import Scope
from hs.engine import Engine, actionable, load_scope, severity_breakdown

SCOPE_DATA = {
    "program": "acme",
    "include": ["example.com", "*.example.com"],
    "authorization": {"authorized_by": "sec@acme.test", "reference": "BB-1"},
}
SCOPE = Scope.from_dict(SCOPE_DATA)

CT_PAYLOAD = json.dumps(
    [
        {"name_value": "www.example.com\napi.example.com", "common_name": "www.example.com"},
        {"name_value": "outro.com", "common_name": "outro.com"},
    ]
)

AWS_KEY = "AKIA" + "3JKL2M9NPQRST7VW"
PAGE_WITH_JS = f'<html><head><title>App</title><script src="/static/app.js"></script></head></html>'
JS_WITH_SECRET = f'const aws = "{AWS_KEY}"; fetch("/api/v1/users");'

ROUTES: dict[str, tuple] = {
    "https://crt.sh/": (200, {}, CT_PAYLOAD),
    "https://www.example.com": (200, {"Server": "nginx/1.24"}, PAGE_WITH_JS),
    "https://www.example.com/static/app.js": (200, {"Content-Type": "application/javascript"}, JS_WITH_SECRET),
    "https://api.example.com": (403, {"Server": "cloudflare"}, "forbidden"),
}


class RouteAdapter(BaseAdapter):
    def __init__(self, routes):
        super().__init__()
        self.routes = {k.rstrip("/"): v for k, v in routes.items()}
        self.calls: list[str] = []

    def send(self, request, **kwargs):
        self.calls.append(request.url)
        entry = self.routes.get(request.url.split("?")[0].rstrip("/"))
        if entry is None:
            raise requests.ConnectionError("sem rota")
        status, headers, body = entry
        r = Response()
        r.status_code = status
        r.url = request.url
        r.request = request
        r.headers = dict(headers or {})
        r._content = body.encode()
        r.encoding = "utf-8"
        r.raw = type("R", (), {"read": lambda s, *a, **k: b"", "release_conn": lambda s: None})()
        return r

    def close(self):
        pass


def make_engine(routes=None, scope=None, **kw):
    adapter = RouteAdapter(routes if routes is not None else ROUTES)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    client = SafeClient(scope or SCOPE, session=session, per_second=0, retries=0)
    return Engine(scope or SCOPE, client=client), adapter


class TestDiscoverHosts:
    def test_junta_seed_e_certificate_transparency(self):
        engine, _ = make_engine()
        hosts = engine.discover_hosts(["example.com"])
        assert "example.com" in hosts
        assert "www.example.com" in hosts
        assert "api.example.com" in hosts

    def test_filtra_fora_do_scope(self):
        engine, _ = make_engine()
        assert "outro.com" not in engine.discover_hosts(["example.com"])

    def test_seed_fora_do_scope_gera_nada(self):
        engine, adapter = make_engine()
        assert engine.discover_hosts(["evil.com"]) == []
        assert adapter.calls == []

    def test_pode_desligar_ct(self):
        engine, adapter = make_engine()
        hosts = engine.discover_hosts(["example.com"], use_ct=False)
        assert hosts == ["example.com"]
        assert not any("crt.sh" in c for c in adapter.calls)

    def test_resultado_deduplicado(self):
        engine, _ = make_engine()
        hosts = engine.discover_hosts(["example.com", "www.example.com"])
        assert hosts == sorted(set(hosts))


class TestRunRecon:
    def test_pipeline_completo(self):
        engine, _ = make_engine()
        result = engine.run_recon(["example.com"])
        assert {a.host for a in result.assets} == {"www.example.com", "api.example.com"}
        assert result.program == "acme"
        assert result.duration_s > 0

    def test_achados_de_header_sao_gerados(self):
        engine, _ = make_engine()
        result = engine.run_recon(["example.com"])
        ids = {f.check_id for f in result.findings}
        assert "missing-csp" in ids
        assert "version-disclosure" in ids

    def test_achado_de_segredo_no_js(self):
        engine, _ = make_engine()
        result = engine.run_recon(["example.com"])
        assert "secret-aws-access-key-id" in {f.check_id for f in result.findings}

    def test_403_ainda_e_auditado(self):
        engine, _ = make_engine()
        result = engine.run_recon(["example.com"])
        assert any(f.asset == "api.example.com" for f in result.findings)

    def test_5xx_e_pulado(self):
        engine, _ = make_engine(routes={**ROUTES, "https://api.example.com": (503, {}, "erro")})
        result = engine.run_recon(["example.com"])
        assert not any(f.asset == "api.example.com" for f in result.findings)

    def test_pode_desligar_probe(self):
        engine, adapter = make_engine()
        result = engine.run_recon(["example.com"], do_probe=False)
        assert all(not a.is_live for a in result.assets)
        assert not any(c.startswith("https://www.example.com") for c in adapter.calls)

    def test_pode_desligar_superficie(self):
        engine, _ = make_engine()
        result = engine.run_recon(["example.com"], do_surface=False)
        assert len(result.findings) == 0

    def test_pode_desligar_ct(self):
        routes = {**ROUTES, "https://example.com": (200, {}, "<title>Root</title>")}
        engine, adapter = make_engine(routes=routes)
        result = engine.run_recon(["example.com"], use_ct=False)
        assert [a.host for a in result.assets] == ["example.com"]
        assert not any("crt.sh" in c for c in adapter.calls)

    def test_sem_seeds(self):
        engine, _ = make_engine()
        result = engine.run_recon([])
        assert result.notes and result.assets == []

    def test_seed_sem_hosts_autorizados(self):
        engine, _ = make_engine()
        result = engine.run_recon(["evil.com"])
        assert "nenhum host autorizado" in result.notes[0]

    def test_deduplica_achados(self):
        engine, _ = make_engine()
        result = engine.run_recon(["example.com"])
        keys = [f.key for f in result.findings]
        assert len(keys) == len(set(keys))

    def test_to_dict_serializavel(self):
        engine, _ = make_engine()
        data = engine.run_recon(["example.com"]).to_dict()
        assert json.dumps(data)
        assert data["counts"]["medium"] >= 1
        assert data["program"] == "acme"

    def test_avisa_quando_scope_desligado(self):
        scope = Scope.from_dict(SCOPE_DATA, bypass=True)
        engine, _ = make_engine(scope=scope)
        result = engine.run_recon(["example.com"])
        assert any("SCOPE DESLIGADO" in n for n in result.notes)

    def test_host_morto_nao_vira_asset(self):
        engine, _ = make_engine(routes={k: v for k, v in ROUTES.items() if "api.example" not in k})
        result = engine.run_recon(["example.com"])
        assert "api.example.com" not in {a.host for a in result.assets}


class TestAuditUrl:
    def test_audita_url_unica(self):
        engine, _ = make_engine()
        findings = engine.audit_url("https://www.example.com")
        assert any(f.check_id == "missing-csp" for f in findings)

    def test_url_fora_do_scope_nao_gera_trafego(self):
        engine, adapter = make_engine()
        assert engine.audit_url("https://evil.com") == []
        assert not any("evil.com" in c for c in adapter.calls)

    def test_url_quebrada_retorna_vazio(self):
        engine, _ = make_engine()
        assert engine.audit_url("https://inexistente.example.com") == []


class TestScanSource:
    def test_varre_diretorio_local(self, tmp_path):
        (tmp_path / "app.js").write_text(f'const k = "{AWS_KEY}";', encoding="utf-8")
        engine, _ = make_engine()
        findings = engine.scan_source(str(tmp_path))
        assert findings[0].check_id == "secret-aws-access-key-id"

    def test_varre_texto(self):
        engine, _ = make_engine()
        findings = engine.scan_text(f'const k = "{AWS_KEY}";', source="bundle.js")
        assert findings[0].asset == "bundle.js"

    def test_extrai_endpoints_de_js(self):
        engine, _ = make_engine()
        assert engine.endpoints_in_js('fetch("/api/v1/users")') == ["/api/v1/users"]


class TestHelpers:
    def test_load_scope(self, tmp_path):
        p = tmp_path / "scope.yaml"
        p.write_text("program: x\ninclude:\n  - a.com\nauthorization:\n  authorized_by: me\n  reference: r\n", encoding="utf-8")
        assert load_scope(str(p)).program == "x"

    def test_load_scope_com_bypass(self, tmp_path):
        p = tmp_path / "scope.yaml"
        p.write_text("program: x\ninclude:\n  - a.com\nauthorization:\n  authorized_by: me\n  reference: r\n", encoding="utf-8")
        assert load_scope(str(p), bypass=True).is_allowed("qualquer.com")

    def test_load_scope_invalido_propaga_erro(self, tmp_path):
        with pytest.raises(Exception):
            load_scope(str(tmp_path / "nao-existe.yaml"))

    def test_severity_breakdown_ignora_zeros(self):
        from hs.core.models import FindingSet

        only_medium = FindingSet(
            [Finding(check_id="a", title="t", severity="medium", asset="a.com")]
        )
        assert severity_breakdown(only_medium) == {"medium": 1}

    def test_actionable_filtra_por_severidade(self):
        engine, _ = make_engine()
        result = engine.run_recon(["example.com"])
        assert all(f.severity.rank >= Severity.MEDIUM.rank for f in actionable(result.findings))

    def test_engine_fecha_client_proprio(self):
        engine = Engine(SCOPE, per_second=0)
        engine.close()

    def test_context_manager(self):
        engine, _ = make_engine()
        with engine as e:
            assert e.scope.program == "acme"

    def test_ngbs_nao_gera_trafego_fora_do_escopo_em_js(self):
        engine, adapter = make_engine(
            routes={
                **ROUTES,
                "https://www.example.com": (200, {}, '<script src="https://evil.com/x.js"></script>'),
            }
        )
        result = engine.run_recon(["example.com"])
        assert not any("evil.com" in c for c in adapter.calls)
        assert not any(f.check_id.startswith("secret-") for f in result.findings)
