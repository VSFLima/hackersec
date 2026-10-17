import json

import pytest
import requests
from requests.adapters import BaseAdapter
from requests.models import Response

from hs import cli
from hs.core.models import Finding, Severity

SCOPE_YAML = """\
program: acme
include:
  - "example.com"
  - "*.example.com"
exclude:
  - "admin.example.com"
authorization:
  authorized_by: "sec@acme.test"
  reference: "BB-1"
"""

AWS_KEY = "AKIA" + "3JKL2M9NPQRST7VW"
PAGE = '<html><head><title>App</title><script src="/static/app.js"></script></head></html>'
ROUTES = {
    "https://crt.sh/": (200, {}, json.dumps([{"name_value": "www.example.com", "common_name": "www.example.com"}])),
    "https://www.example.com": (200, {"Server": "nginx/1.24"}, PAGE),
    "https://www.example.com/static/app.js": (200, {}, f'const k = "{AWS_KEY}";'),
}


class RouteAdapter(BaseAdapter):
    ROUTES = {k.rstrip("/"): v for k, v in ROUTES.items()}

    def send(self, request, **kwargs):
        entry = self.ROUTES.get(request.url.split("?")[0].rstrip("/"))
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


@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(SCOPE_YAML, encoding="utf-8")
    return p


@pytest.fixture
def offline(monkeypatch):
    def install():
        def fake_session(*a, **kw):
            s = requests.Session()
            s.mount("https://", RouteAdapter())
            s.mount("http://", RouteAdapter())
            return s

        monkeypatch.setattr(cli.SafeClient, "__init__", _patched_init(fake_session))

    return install


def _patched_init(session_factory):
    original = cli.SafeClient.__init__

    def wrapper(self, scope, **kwargs):
        original(self, scope, session=session_factory(), **kwargs)

    return wrapper


class TestInit:
    def test_cria_scope_de_exemplo(self, tmp_path, capsys):
        out = tmp_path / "scope.yaml"
        assert cli.main(["init", "-o", str(out)]) == 0
        assert out.exists()
        assert "authorization" in out.read_text(encoding="utf-8")

    def test_recusa_sobrescrever(self, tmp_path):
        out = tmp_path / "scope.yaml"
        out.write_text("existente", encoding="utf-8")
        assert cli.main(["init", "-o", str(out)]) == 1

    def test_template_e_scope_valido(self, tmp_path):
        out = tmp_path / "scope.yaml"
        cli.main(["init", "-o", str(out)])
        from hs.core.scope import Scope

        scope = Scope.from_file(out)
        assert scope.is_allowed("www.example.com")


class TestEscopoObrigatorio:
    def test_recon_sem_scope_falha(self, tmp_path, capsys):
        assert cli.main(["recon", "example.com", "-o", str(tmp_path / "out")]) == 1
        assert "escopo obrigatorio" in capsys.readouterr().err

    def test_audit_sem_scope_falha(self, tmp_path):
        assert cli.main(["audit", "https://example.com", "-o", str(tmp_path / "out")]) == 1

    def test_secrets_sem_scope_falha(self, tmp_path):
        assert cli.main(["secrets", str(tmp_path), "-o", str(tmp_path / "out")]) == 1

    def test_no_scope_desliga_validacao(self, tmp_path, offline, monkeypatch):
        offline()
        assert cli.main(["secrets", str(tmp_path), "--no-scope", "-o", str(tmp_path / "out")]) in (0, 2)

    def test_scope_inexistente_falha(self, tmp_path, capsys):
        assert cli.main(["audit", "https://x.com", "--scope", str(tmp_path / "nao.yaml")]) == 1
        assert "erro de escopo" in capsys.readouterr().err

    def test_scope_sem_autorizacao_falha(self, tmp_path, capsys):
        bad = tmp_path / "bad.yaml"
        bad.write_text("program: x\ninclude:\n  - a.com\n", encoding="utf-8")
        assert cli.main(["audit", "https://a.com", "--scope", str(bad)]) == 1
        assert "authorized_by" in capsys.readouterr().err


class TestSecrets:
    def test_gera_relatorio_quando_ha_achado(self, tmp_path, scope_file, capsys):
        src = tmp_path / "app.js"
        src.write_text(f'const k = "{AWS_KEY}";', encoding="utf-8")
        out = tmp_path / "out"
        assert cli.main(["secrets", str(src), "--scope", str(scope_file), "-o", str(out)]) == 0
        assert (out / "00-index.md").exists()
        assert (out / "report.html").exists()
        assert (out / "findings.json").exists()
        assert (out / "run.json").exists()
        assert "1" in capsys.readouterr().out

    def test_codigo_de_saida_2_quando_nada_encontrado(self, tmp_path, scope_file):
        src = tmp_path / "app.js"
        src.write_text("var a = 1;", encoding="utf-8")
        assert cli.main(["secrets", str(src), "--scope", str(scope_file), "-o", str(tmp_path / "out")]) == 2

    def test_relatorio_individual_gerado(self, tmp_path, scope_file):
        src = tmp_path / "app.js"
        src.write_text(f'const k = "{AWS_KEY}";', encoding="utf-8")
        out = tmp_path / "out"
        cli.main(["secrets", str(src), "--scope", str(scope_file), "-o", str(out)])
        assert (out / "reports" / "secret-aws-access-key-id-1.md").exists()

    def test_run_json_e_parseavel(self, tmp_path, scope_file):
        src = tmp_path / "app.js"
        src.write_text(f'const k = "{AWS_KEY}";', encoding="utf-8")
        out = tmp_path / "out"
        cli.main(["secrets", str(src), "--scope", str(scope_file), "-o", str(out)])
        data = json.loads((out / "run.json").read_text(encoding="utf-8"))
        assert data["counts"]["critical"] == 1

    def test_nome_researcher_assina_relatorio(self, tmp_path, scope_file):
        src = tmp_path / "app.js"
        src.write_text(f'const k = "{AWS_KEY}";', encoding="utf-8")
        out = tmp_path / "out"
        cli.main(["secrets", str(src), "--scope", str(scope_file), "-o", str(out), "--researcher", "ana"])
        assert "ana" in (out / "reports" / "secret-aws-access-key-id-1.md").read_text(encoding="utf-8")


class TestRecon:
    def test_pipeline_gera_saida(self, tmp_path, scope_file, offline, capsys):
        offline()
        out = tmp_path / "out"
        assert cli.main(["recon", "example.com", "--scope", str(scope_file), "-o", str(out)]) == 0
        data = json.loads((out / "run.json").read_text(encoding="utf-8"))
        assert data["program"] == "acme"
        assert any(f["check_id"] == "secret-aws-access-key-id" for f in data["findings"])

    def test_flags_de_desativacao(self, tmp_path, scope_file, offline):
        offline()
        out = tmp_path / "out"
        assert (
            cli.main(
                [
                    "recon",
                    "example.com",
                    "--scope",
                    str(scope_file),
                    "-o",
                    str(out),
                    "--no-surface",
                    "--no-probe",
                ]
            )
            == 0
        )
        data = json.loads((out / "run.json").read_text(encoding="utf-8"))
        assert data["findings"] == []

    def test_seed_fora_do_scope_gera_relatorio_vazio(self, tmp_path, scope_file, offline, capsys):
        offline()
        out = tmp_path / "out"
        assert cli.main(["recon", "evil.com", "--scope", str(scope_file), "-o", str(out)]) == 0
        assert "nenhum host autorizado" in capsys.readouterr().out


class TestAudit:
    def test_audita_url(self, tmp_path, scope_file, offline):
        offline()
        out = tmp_path / "out"
        assert cli.main(["audit", "https://www.example.com", "--scope", str(scope_file), "-o", str(out)]) == 0
        data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        assert any(f["check_id"] == "missing-csp" for f in data["findings"])

    def test_url_fora_do_scope_sem_achados(self, tmp_path, scope_file, offline):
        offline()
        out = tmp_path / "out"
        assert cli.main(["audit", "https://evil.com", "--scope", str(scope_file), "-o", str(out)]) == 2


class TestGeral:
    def test_sem_comando_mostra_ajuda(self, capsys):
        assert cli.main([]) == 1
        assert "hackersec" in capsys.readouterr().out

    def test_versao(self, capsys):
        assert cli.main(["--version"]) == 0
        assert "hackersec" in capsys.readouterr().out

    def test_help_dos_subcomandos(self, capsys):
        for command in ("init", "recon", "audit", "secrets"):
            with pytest.raises(SystemExit):
                cli.main([command, "--help"])

    def test_rate_e_insecure_sao_aceitos(self, tmp_path, scope_file, capsys):
        src = tmp_path / "a.js"
        src.write_text("var a = 1;", encoding="utf-8")
        assert cli.main(
            ["secrets", str(src), "--scope", str(scope_file), "-o", str(tmp_path / "o"), "--rate", "1", "--insecure"]
        ) == 2


class TestWriteReports:
    def test_escapa_nomes_de_arquivo(self, tmp_path):
        from hs.core.models import FindingSet
        from hs.core.scope import Scope
        from hs.engine import RunResult

        result = RunResult(
            program="p",
            findings=FindingSet([Finding(check_id="weird/id", title="T", severity=Severity.LOW)]),
        )
        scope = Scope.from_dict(
            {"program": "p", "include": ["a.com"], "authorization": {"authorized_by": "me", "reference": "r"}}
        )
        out = cli.write_reports(result, scope, str(tmp_path / "o"), "hackerone", "")
        assert (out / "00-index.md").exists()
        assert not any(".." in p.name for p in (out / "reports").iterdir())
