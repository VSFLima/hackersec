import pytest

from hs.core.scope import Scope, ScopeError

BASE = {
    "program": "acme-bounty",
    "include": ["example.com", "*.example.com"],
    "exclude": ["admin.example.com", "billing.example.com"],
    "authorization": {"authorized_by": "security@acme.test", "reference": "BB-2026-01"},
}


def make(**overrides):
    data = {**BASE, **overrides}
    return Scope.from_dict(data)


class TestCarregamento:
    def test_carrega_scope_valido(self):
        scope = make()
        assert scope.program == "acme-bounty"
        assert scope.authorized_by == "security@acme.test"
        assert scope.authorization_ref == "BB-2026-01"

    def test_recusa_scope_sem_include(self):
        with pytest.raises(ScopeError, match="deny-by-default"):
            Scope.from_dict({**BASE, "include": []})

    def test_recusa_scope_sem_autorizacao(self):
        data = {**BASE, "authorization": {}}
        with pytest.raises(ScopeError, match="authorized_by"):
            Scope.from_dict(data)

    def test_recusa_yaml_inexistente(self, tmp_path):
        with pytest.raises(ScopeError, match="nao encontrado"):
            Scope.from_file(tmp_path / "nao-existe.yaml")

    def test_recusa_lista_invalida(self):
        with pytest.raises(ScopeError, match="include"):
            Scope.from_dict({**BASE, "include": "example.com"})

    def test_le_arquivo_yaml(self, tmp_path):
        p = tmp_path / "scope.yaml"
        p.write_text(
            "program: demo\ninclude:\n  - alvo.test\nauthorization:\n  authorized_by: me\n  reference: r1\n",
            encoding="utf-8",
        )
        assert Scope.from_file(p).program == "demo"


class TestAllowlist:
    @pytest.mark.parametrize(
        "target",
        [
            "example.com",
            "www.example.com",
            "https://example.com",
            "https://www.example.com/login",
            "EXAMPLE.COM",
            "example.com.",
        ],
    )
    def test_permite_alvos_dentro_do_escopo(self, target):
        assert make().is_allowed(target)

    @pytest.mark.parametrize(
        "target",
        [
            "evil.com",
            "example.com.evil.com",
            "notexample.com",
            "sub.notexample.com",
            "https://evil.com/?x=example.com",
        ],
    )
    def test_bloqueia_alvos_fora_do_escopo(self, target):
        assert not make().is_allowed(target)

    def test_bloqueia_sufixo_de_terceiros(self):
        decision = make().check("example.com.evil.com")
        assert not decision.allowed
        assert "fora do escopo" in decision.reason


class TestExclude:
    def test_exclude_tem_precedencia_sobre_include(self):
        scope = make()
        assert scope.is_allowed("www.example.com")
        assert not scope.is_allowed("admin.example.com")
        assert not scope.is_allowed("billing.example.com")

    def test_exclude_por_wildcard(self):
        scope = make(exclude=["*.internal.example.com"])
        assert not scope.is_allowed("vault.internal.example.com")
        assert scope.is_allowed("www.example.com")

    def test_reporta_regra_que_gerou_bloqueio(self):
        decision = make().check("admin.example.com")
        assert decision.matched_rule == "admin.example.com"


class TestPortas:
    def test_permite_porta_declarada(self):
        scope = make(allowed_ports=[80, 443, 9000])
        assert scope.is_allowed("example.com:9000")

    def test_bloqueia_porta_fora_da_lista(self):
        scope = make(allowed_ports=[80, 443])
        decision = scope.check("example.com:22")
        assert not decision.allowed
        assert "22" in decision.reason

    def test_porta_embutida_em_url(self):
        scope = make(allowed_ports=[443])
        assert scope.is_allowed("https://example.com:443/x")

    def test_porta_por_regra(self):
        scope = make(include=["example.com:8443"], allowed_ports=[443, 8443])
        assert scope.is_allowed("example.com:8443")
        assert not scope.is_allowed("example.com:443")


class TestExtensoesNegadas:
    @pytest.mark.parametrize("path", ["/a/logo.png", "/y/font.woff2", "/s/site.css"])
    def test_bloqueia_extensao_negada(self, path):
        decision = make().check(f"https://example.com{path}")
        assert not decision.allowed
        assert "extensao negada" in decision.reason

    def test_permite_paginas_sem_extensao(self):
        assert make().is_allowed("https://example.com/admin/users")

    def test_js_continua_autorizado_para_varredura_de_segredos(self):
        assert make().is_allowed("https://example.com/static/app.js")


class TestRede:
    def test_permite_cidr(self):
        scope = make(include=["10.0.0.0/8"], exclude=[])
        assert scope.is_allowed("10.1.2.3")
        assert not scope.is_allowed("192.168.1.1")

    def test_exclude_cidr_tem_precedencia(self):
        scope = make(include=["10.0.0.0/8"], exclude=["10.5.0.0/16"])
        assert scope.is_allowed("10.1.1.1")
        assert not scope.is_allowed("10.5.1.1")


class TestBypass:
    def test_bypass_ignora_include(self):
        scope = Scope.from_dict(BASE, bypass=True)
        assert scope.is_allowed("qualquer-coisa.com")

    def test_bypass_marca_a_decisao_como_nao_verificada(self):
        scope = Scope.from_dict(BASE, bypass=True)
        decision = scope.check("qualquer-coisa.com")
        assert "NAO VERIFICADO" in decision.reason

    def test_bypass_nao_exige_autorizacao(self):
        scope = Scope.from_dict(
            {"program": "lab", "include": [], "authorization": {}}, bypass=True
        )
        assert scope.is_allowed("127.0.0.1")

    def test_sem_bypass_modo_normal_e_bloqueante(self):
        assert not Scope.from_dict(BASE).is_allowed("qualquer-coisa.com")


class TestFiltroEmLote:
    def test_particiona_lista(self):
        allowed, denied = make().filter(
            ["example.com", "evil.com", "www.example.com", "admin.example.com"]
        )
        assert allowed == ["example.com", "www.example.com"]
        assert [d.host for d in denied] == ["evil.com", "admin.example.com"]


class TestEntradasInvalidas:
    @pytest.mark.parametrize("target", ["", "   ", "///"])
    def test_alvo_vazio_ou_invalido(self, target):
        decision = make().check(target)
        assert not decision.allowed
        assert decision.reason

    def test_url_com_credenciais_nao_confunde_o_host(self):
        assert make().is_allowed("https://user:evil.com@example.com/")

    def test_unicode_e_espacos(self):
        assert make().is_allowed("  WWW.Example.COM  ")
