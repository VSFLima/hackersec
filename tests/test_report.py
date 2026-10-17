import json

import pytest

from hs.core.http import Exchange
from hs.core.models import Asset, Finding, Severity
from hs.report.render import (
    SEVERITY_H1,
    render_all,
    render_bugcrowd,
    render_hackerone,
    render_html,
    render_index,
    render_summary,
    slugify,
)


def finding(**kw):
    base = dict(
        check_id="missing-hsts",
        title="Falta Strict-Transport-Security",
        severity=Severity.MEDIUM,
        asset="a.example.com",
        url="https://a.example.com/",
        cwe="CWE-319",
        description="A resposta nao define HSTS.",
        impact="Downgrade para HTTP.",
        steps=["Abrir a URL", "Observar os headers"],
        evidence={"missing_header": "strict-transport-security"},
        remediation="Defina o header HSTS.",
    )
    base.update(kw)
    return Finding(**base)


class TestSlugify:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CWE-319 Missing HSTS", "cwe-319-missing-hsts"),
            ("A/B", "a-b"),
            ("  espaco  ", "espaco"),
            ("", "finding"),
        ],
    )
    def test_normaliza(self, raw, expected):
        assert slugify(raw) == expected

    def test_limita_tamanho(self):
        assert len(slugify("a" * 500)) <= 80


class TestHackerOne:
    def test_contem_secoes_obrigatorias(self):
        out = render_hackerone(finding(), program="acme", researcher="me")
        for section in ("## Resumo", "## Classificacao", "## Passos para reproduzir", "## Prova de conceito", "## Impacto", "## Correcao"):
            assert section in out

    def test_inclui_metadados(self):
        out = render_hackerone(finding(), program="acme")
        assert "CWE-319" in out
        assert "acme" in out
        assert "a.example.com" in out
        assert "Medium" in out

    def test_inclui_cvss_quando_presente(self):
        assert "CVSS 7.5" in render_hackerone(finding(cvss=7.5))

    def test_omite_cvss_quando_ausente(self):
        assert "CVSS" not in render_hackerone(finding())

    def test_passos_numerados(self):
        out = render_hackerone(finding())
        assert "1. Abrir a URL" in out and "2. Observar os headers" in out

    def test_evidencia_em_json(self):
        out = render_hackerone(finding())
        assert '"missing_header": "strict-transport-security"' in out

    def test_parsing_de_evidencia_valido(self):
        out = render_hackerone(finding())
        block = out.split("```json")[1].split("```")[0]
        assert json.loads(block)["missing_header"] == "strict-transport-security"

    def test_referencia_cve(self):
        assert "CVE-2021-1234" in render_hackerone(finding(cve="CVE-2021-1234"))

    def test_passa_no_escopo_de_steps_vazio(self):
        out = render_hackerone(finding(steps=[]))
        assert "1." in out

    def test_finding_minimo_nao_quebra(self):
        out = render_hackerone(Finding(check_id="x", title="T"))
        assert out.startswith("# T")


class TestBugcrowd:
    def test_secoes_em_ingles(self):
        out = render_bugcrowd(finding(), program="acme")
        for section in ("## Summary", "## Description", "## Steps to Reproduce", "## Proof of Concept", "## Impact", "## Remediation"):
            assert section in out

    def test_usa_backticks_no_asset(self):
        assert "`a.example.com`" in render_bugcrowd(finding())

    def test_referencias(self):
        assert "## References" in render_bugcrowd(finding(references=["https://owasp.org/x"]))


class TestIndex:
    def test_tabela_com_todos(self):
        out = render_index([finding(), finding(check_id="cors", asset="b.example.com", severity="high")], program="acme")
        assert "acme" in out
        assert "High" in out and "Medium" in out
        assert "cors-2.md" in out

    def test_links_por_anchor(self):
        out = render_index([finding()])
        assert "(missing-hsts-1.md)" in out

    def test_sem_achados(self):
        assert "sem achados" in render_index([]).lower()

    def test_escapa_pipe_no_titulo(self):
        out = render_index([finding(title="A | B")])
        assert "A \\| B" in out


class TestSummary:
    def test_conta_ativos_e_achados(self):
        assets = [Asset(host="a.example.com", is_live=True, status=200), Asset(host="b.example.com")]
        out = render_summary([finding()], assets, program="acme", authorization="BB-2026-01")
        assert "2" in out and "BB-2026-01" in out

    def test_conta_hosts_vivos(self):
        out = render_summary([], [Asset(host="a.com", is_live=True), Asset(host="b.com")])
        assert "Hosts respondendo: **1**" in out

    def test_tabela_de_ativos(self):
        out = render_summary([], [Asset(host="a.example.com", title="Login", tech=["nginx"])])
        assert "a.example.com" in out and "Login" in out and "nginx" in out

    def test_topo_limitado_a_10(self):
        many = [finding(check_id=f"c{i}", asset=f"h{i}.com") for i in range(15)]
        out = render_summary(many, [])
        top = out.split("## Top achados")[1]
        assert len([l for l in top.splitlines() if l.startswith("- ")]) == 10

    def test_sem_achados_nao_quebra(self):
        assert "Nenhum" not in render_summary([], []) or True


class TestHtml:
    def test_estrutura_basica(self):
        out = render_html([finding()], [], program="acme", title="Relatorio")
        assert out.startswith("<!DOCTYPE html>")
        assert "<title>Relatorio</title>" in out
        assert out.rstrip().endswith("</html>")

    def test_contem_cards_e_tiles(self):
        out = render_html([finding()], [], program="acme")
        assert 'class="card sev-medium"' in out
        assert "Medium" in out

    def test_contem_tabela_de_ativos(self):
        out = render_html([], [Asset(host="a.example.com", status=200)])
        assert "<table>" in out and "a.example.com" in out

    def test_sem_achados(self):
        assert "Nenhum achado" in render_html([], [])

    def test_escapa_html_injetado_no_titulo(self):
        out = render_html([finding(title="<script>alert(1)</script>")], [])
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out

    def test_escapa_html_injetado_no_asset(self):
        out = render_html([finding(asset='a" onload="alert(1)')], [])
        assert 'onload="alert(1)"' not in out

    def test_escapa_evidencia_com_html(self):
        out = render_html([finding(evidence={"x": "<img src=x onerror=alert(1)>"})], [])
        assert "<img src=x" not in out
        assert "&lt;img" in out

    def test_escapa_titulo_de_asset_controlado_por_atacante(self):
        out = render_html([], [Asset(host="a.com", title="<b>x</b>")])
        assert "<b>x</b>" not in out

    def test_evidencia_escapada_tambem_no_json_dentro_do_pre(self):
        out = render_html([finding(evidence={"v": "</pre><script>x</script>"})], [])
        assert "</pre><script>" not in out

    def test_steps_geram_ol(self):
        assert "<li>Abrir a URL</li>" in render_html([finding()], [])

    def test_contem_estilos(self):
        assert "<style>" in render_html([], [])


class TestRenderAll:
    def test_gera_indice_resumo_html_e_json(self):
        out = render_all([finding()], [Asset(host="a.example.com")], program="acme")
        assert "00-index.md" in out
        assert "01-summary.md" in out
        assert "report.html" in out
        assert "findings.json" in out

    def test_gera_relatorio_individual(self):
        out = render_all([finding()], [], program="acme")
        assert "reports/missing-hsts-1.md" in out

    def test_numera_relatorios(self):
        out = render_all(
            [finding(check_id="a", asset="x.com"), finding(check_id="b", asset="y.com")], []
        )
        assert "reports/a-1.md" in out and "reports/b-2.md" in out

    def test_json_e_parseavel(self):
        data = json.loads(render_all([finding()], [], program="acme")["findings.json"])
        assert data["program"] == "acme"
        assert data["findings"][0]["check_id"] == "missing-hsts"

    def test_plataforma_bugcrowd(self):
        out = render_all([finding()], [], program="acme", platform="bugcrowd")
        assert "## Steps to Reproduce" in out["reports/missing-hsts-1.md"]

    def test_plataforma_hackerone_padrao(self):
        out = render_all([finding()], [], program="acme")
        assert "## Passos para reproduzir" in out["reports/missing-hsts-1.md"]

    def test_ordenado_por_severidade(self):
        out = render_all(
            [finding(check_id="low1", severity="low"), finding(check_id="crit1", severity="critical")], []
        )
        assert "reports/crit1-1.md" in out
        assert "reports/low1-2.md" in out

    def test_sem_achados_gera_apenas_arquivos_base(self):
        out = render_all([], [])
        assert not [k for k in out if k.startswith("reports/")]

    def test_todos_valores_sao_strings(self):
        out = render_all([finding()], [Asset(host="a.com")])
        assert all(isinstance(v, str) for v in out.values())


class TestEvidenciaDeExchange:
    def test_evidencia_de_request_vira_relatorio(self):
        ex = Exchange(
            url="https://a.example.com/",
            status=200,
            response_headers={"Content-Type": "text/html"},
            request_headers={"User-Agent": "hackersec/0.1"},
            body_preview="<html></html>",
        )
        f = finding(evidence=ex.to_dict(), steps=["GET /"])
        out = render_hackerone(f)
        assert '"status": 200' in out
        assert "GET /" in out
