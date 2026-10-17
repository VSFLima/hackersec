import pytest

from hs.checks.secrets import (
    MIN_ENTROPY,
    Match,
    extract_js_endpoints,
    is_documented_placeholder,
    is_placeholder,
    iter_source_files,
    mask,
    scan_path,
    scan_secrets,
    shannon_entropy,
    to_findings,
)
from hs.core.models import Severity

AWS_KEY = "AKIA" + "3JKL2M9NPQRST7VW"
GITHUB_PAT = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
GOOGLE_KEY = "AIza" + ("b1C2d3E4f5G6h7I8j9K0" * 2)[:35]


def only(text, **kw):
    matches = scan_secrets(text, **kw)
    return matches


class TestEntropy:
    def test_texto_aleatorio_tem_alta_entropia(self):
        assert shannon_entropy(GITHUB_PAT) > MIN_ENTROPY

    def test_texto_repetitivo_tem_baixa_entropia(self):
        assert shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0

    def test_vazio_retorna_zero(self):
        assert shannon_entropy("") == 0.0


class TestMask:
    def test_mantem_inicio_e_fim(self):
        assert mask("AKIA3JKL2M9NPQRST7VW") == "AKIA************T7VW"

    def test_valor_curto_vira_asteriscos(self):
        assert mask("abc") == "***"

    def test_nao_vaza_o_meio(self):
        assert "JKL2M9" not in mask("AKIA3JKL2M9NPQRST7VW")


class TestPlaceholderFilters:
    @pytest.mark.parametrize(
        "value", ["YOUR_API_KEY", "changeme", "<your-key>", "${SECRET}", "{{token}}", "aaaaaaaa", "null"]
    )
    def test_agressivo_rejeita(self, value):
        assert is_placeholder(value)

    def test_agressivo_aceita_credencial_real(self):
        assert not is_placeholder(AWS_KEY)

    def test_conservador_rejeita_exemplo_da_documentacao_aws(self):
        assert is_documented_placeholder("AKIAIOSFODNN7EXAMPLE")

    def test_conservador_rejeita_marcadores(self):
        assert is_documented_placeholder("sk_test_XXXXXXXXXXXX")

    def test_conservador_aceita_chave_real(self):
        assert not is_documented_placeholder(AWS_KEY)
        assert not is_documented_placeholder(GITHUB_PAT)


class TestPadroesDeAltaConfianca:
    @pytest.mark.parametrize(
        "text,pattern_id,severity",
        [
            (f'aws = "{AWS_KEY}"', "aws-access-key-id", Severity.CRITICAL),
            (f'token = "{GITHUB_PAT}"', "github-pat", Severity.CRITICAL),
            (f'k = "{GOOGLE_KEY}"', "google-api-key", Severity.HIGH),
            ("-----BEGIN RSA PRIVATE KEY-----", "private-key-block", Severity.CRITICAL),
            ("-----BEGIN PRIVATE KEY-----", "private-key-block", Severity.CRITICAL),
            ("url: https://admin:Sup3rS3cr3t@internal.corp/", "url-embedded-credentials", Severity.HIGH),
        ],
    )
    def test_detecta(self, text, pattern_id, severity):
        matches = only(text)
        assert pattern_id in {m.pattern_id for m in matches}
        assert next(m for m in matches if m.pattern_id == pattern_id).severity is severity

    def test_ignora_exemplo_documentado_da_aws(self):
        assert only('k = "AKIAIOSFODNN7EXAMPLE"') == []

    def test_ignora_placeholders(self):
        assert only('k = "YOUR_API_KEY_HERE_XXXXXXXX"') == []

    def test_marca_linha_e_coluna(self):
        matches = only(f'const a = 1;\nconst k = "{AWS_KEY}";')
        assert matches[0].line == 2
        assert matches[0].column > 0

    def test_mascara_valor_encontrado(self):
        assert AWS_KEY not in only(f'k = "{AWS_KEY}"')[0].masked

    def test_nao_duplica_mesmo_valor_na_mesma_linha(self):
        text = f'a = "{AWS_KEY}"; b = "{AWS_KEY}";'
        matches = [m for m in only(text) if m.pattern_id == "aws-access-key-id"]
        assert len({m.line for m in matches}) == 1

    def test_resultado_ordenado_por_linha(self):
        text = f'a = "{GITHUB_PAT}";\nb = "{AWS_KEY}";'
        matches = only(text)
        assert [m.line for m in matches] == sorted(m.line for m in matches)

    def test_texto_vazio(self):
        assert only("") == []


class TestDetectorGenerico:
    def test_detecta_valor_com_alta_entropia(self):
        matches = only('password = "9fj2Kq83LmZx01Pq"')
        assert any(m.pattern_id == "generic-api-key" for m in matches)

    def test_ignora_valor_de_baixa_entropia(self):
        assert not any(
            m.pattern_id == "generic-api-key" for m in only('password = "aaaa"')
        )

    def test_ignora_placeholder(self):
        assert only('api_key = "your_api_key_here_x"') == []

    def test_ignora_string_vazia(self):
        assert only('password = ""') == []

    def test_confianca_baixa(self):
        m = next(m for m in only('password = "9fj2Kq83LmZx01Pq"') if m.pattern_id == "generic-api-key")
        assert m.confidence == "low"

    def test_pode_ser_desligado(self):
        assert only('password = "9fj2Kq83LmZx01Pq"', allow_generic=False) == []

    def test_nao_duplica_padrao_especifico(self):
        matches = only(f'aws_key = "{AWS_KEY}"')
        patterns = [m.pattern_id for m in matches]
        assert patterns.count("aws-access-key-id") == 1
        assert "generic-api-key" not in patterns


class TestJsEndpoints:
    def test_extrai_paths_de_api(self):
        assert extract_js_endpoints('fetch("/api/v1/users")') == ["/api/v1/users"]

    def test_extrai_urls_absolutas(self):
        assert extract_js_endpoints('var u = "https://api.example.com/rest/thing"') == [
            "https://api.example.com/rest/thing"
        ]

    def test_aceita_aspas_simples_e_backtick(self):
        assert extract_js_endpoints("x('/graphql') + y(`/internal/debug`)") == [
            "/graphql",
            "/internal/debug",
        ]

    def test_deduplica_e_ordena(self):
        assert extract_js_endpoints('"/api/a" "/api/b" "/api/a"') == ["/api/a", "/api/b"]

    def test_ignora_paths_nao_interessantes(self):
        assert extract_js_endpoints('var p = "/css/main.css"') == []

    def test_bundle_vazio(self):
        assert extract_js_endpoints("") == []


class TestScanPath:
    def test_varre_diretorio(self, tmp_path):
        (tmp_path / "app.js").write_text(f'const k = "{AWS_KEY}";', encoding="utf-8")
        (tmp_path / "config.json").write_text('{"api_key": "' + GOOGLE_KEY + '"}', encoding="utf-8")
        patterns = {m.pattern_id for m in scan_path(tmp_path)}
        assert "aws-access-key-id" in patterns
        assert "google-api-key" in patterns

    def test_respeita_ignore(self, tmp_path):
        node_modules = tmp_path / "node_modules"
        node_modules.mkdir()
        (node_modules / "dep.js").write_text(f'const k = "{AWS_KEY}";', encoding="utf-8")
        assert scan_path(tmp_path) == []

    def test_varre_ficheiro_unico(self, tmp_path):
        f = tmp_path / ".env"
        f.write_text(f'AWS_ACCESS_KEY_ID={AWS_KEY}\n', encoding="utf-8")
        assert len(scan_path(f)) == 1

    def test_captura_dotenv(self, tmp_path):
        (tmp_path / ".env").write_text("A=1", encoding="utf-8")
        assert (tmp_path / ".env").name in {p.name for p in iter_source_files(tmp_path)}

    def test_respeita_max_files(self, tmp_path):
        for i in range(5):
            (tmp_path / f"f{i}.js").write_text("var a = 1;", encoding="utf-8")
        assert scan_path(tmp_path, max_files=2) == []


class TestToFindings:
    def _match(self, **kw):
        base = dict(
            pattern_id="aws-access-key-id",
            name="AWS Access Key ID",
            value=AWS_KEY,
            severity=Severity.CRITICAL,
            cwe="CWE-798",
            confidence="high",
            line=3,
            column=7,
            masked="AKIA************T7VW",
            source="app.js",
        )
        base.update(kw)
        return Match(**base)

    def test_gera_finding_com_metadados(self):
        f = self._match().to_finding()
        assert f.check_id == "secret-aws-access-key-id"
        assert f.severity is Severity.CRITICAL
        assert f.cwe == "CWE-798"
        assert f.source == "hackersec"
        assert f.asset == "app.js"
        assert f.evidence["source"] == "app.js"

    def test_finding_nao_contem_o_segredo_em_clear(self):
        assert AWS_KEY not in str(self._match().to_finding().to_dict())

    def test_finding_tem_passos_e_remediacao(self):
        f = self._match().to_finding()
        assert f.steps and f.remediation

    def test_to_findings_preserva_ordem(self):
        findings = to_findings([self._match(line=1), self._match(line=2, source="b.js")])
        assert [f.asset for f in findings] == ["app.js", "b.js"]
