import pytest

from hs.core.models import Asset, Finding, FindingSet, Severity, normalize_url, severity_from


class TestSeverity:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("high", Severity.HIGH),
            ("HIGH", Severity.HIGH),
            ("Critical", Severity.CRITICAL),
            ("crit", Severity.CRITICAL),
            ("informational", Severity.INFO),
            ("none", Severity.INFO),
            ("moderate", Severity.MEDIUM),
            ("desconhecido", Severity.LOW),
        ],
    )
    def test_parse_de_aliases(self, raw, expected):
        assert severity_from(raw) is expected

    def test_ordenacao_por_rank(self):
        assert sorted([Severity.CRITICAL, Severity.LOW, Severity.HIGH]) == [
            Severity.LOW,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

    def test_rank_numerico(self):
        assert Severity.INFO.rank < Severity.LOW.rank < Severity.MEDIUM.rank
        assert Severity.HIGH.rank < Severity.CRITICAL.rank

    def test_label(self):
        assert Severity.MEDIUM.label == "Medium"


class TestNormalizeUrl:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("HTTPS://WWW.Example.COM//a//b", "https://example.com/a/b"),
            ("https://example.com:443/x", "https://example.com/x"),
            ("http://example.com:80/x", "http://example.com/x"),
            ("https://example.com:8443/x", "https://example.com:8443/x"),
            ("https://example.com", "https://example.com/"),
        ],
    )
    def test_normaliza(self, raw, expected):
        assert normalize_url(raw) == expected

    def test_remove_fragmento_mantem_query(self):
        assert normalize_url("https://a.com/p?x=1#frag") == "https://a.com/p?x=1"


class TestAsset:
    def test_normaliza_host_e_url(self):
        asset = Asset(host="WWW.Example.COM.", url="https://www.example.com")
        assert asset.host == "www.example.com"
        assert asset.scheme == "https"

    def test_deriva_host_da_url(self):
        assert Asset(url="https://api.example.com/v1").host == "api.example.com"

    def test_deriva_url_do_host(self):
        assert Asset(host="api.example.com", scheme="https").url == "https://api.example.com"

    def test_tech_normalizada_e_deduplicada(self):
        asset = Asset(host="a.com", tech=["Nginx", "nginx", " PHP ", ""])
        assert asset.tech == ["nginx", "php"]

    def test_key_inclui_porta_efetiva(self):
        assert Asset(host="a.com", scheme="https").key == "https://a.com:443"
        assert Asset(host="a.com", scheme="http", port=8080).key == "http://a.com:8080"

    def test_roundtrip_dict(self):
        asset = Asset(host="a.com", status=200, tech=["nginx"], is_live=True)
        assert Asset.from_dict(asset.to_dict()) == asset

    def test_from_dict_ignora_campos_desconhecidos(self):
        assert Asset.from_dict({"host": "a.com", "campo_inexistente": 1}).host == "a.com"


class TestFinding:
    def test_normaliza_cwe(self):
        assert Finding(check_id="x", title="t", cwe="cwe-79").cwe == "CWE-79"
        assert Finding(check_id="x", title="t", cwe="CWE 89").cwe == "CWE-89"
        assert Finding(check_id="x", title="t", cwe="").cwe == ""

    def test_normaliza_cve_e_cvss(self):
        f = Finding(check_id="x", title="t", cve="cve-2021-1234", cvss=12.7)
        assert f.cve == "CVE-2021-1234"
        assert f.cvss == 10.0

    def test_cvss_negativo_e_limitado(self):
        assert Finding(check_id="x", title="t", cvss=-3).cvss == 0.0

    def test_deriva_asset_da_url(self):
        f = Finding(check_id="x", title="t", url="https://api.example.com/v1/users")
        assert f.asset == "api.example.com"

    def test_severity_string_e_convertida(self):
        assert Finding(check_id="x", title="t", severity="high").severity is Severity.HIGH

    def test_fingerprint_estavel(self):
        a = Finding(check_id="tls", title="t", url="https://a.com/x")
        b = Finding(check_id="tls", title="titulo diferente", url="https://a.com/x")
        assert a.fingerprint == b.fingerprint

    def test_fingerprint_diferente_por_check_e_host(self):
        base = Finding(check_id="tls", title="t", url="https://a.com/x")
        assert base.fingerprint != Finding(check_id="hdr", title="t", url="https://a.com/x").fingerprint
        assert base.fingerprint != Finding(check_id="tls", title="t", url="https://b.com/x").fingerprint

    def test_fingerprint_ignora_query_e_caixa(self):
        a = Finding(check_id="tls", title="t", url="https://a.com/x?a=1")
        b = Finding(check_id="tls", title="t", url="HTTPS://A.com//x")
        assert a.fingerprint == b.fingerprint

    def test_fingerprint_tem_16_chars(self):
        assert len(Finding(check_id="tls", title="t", url="https://a.com").fingerprint) == 16

    def test_tags_normalizadas(self):
        f = Finding(check_id="x", title="t", tags=["TLS", "tls", " Header ", ""])
        assert f.tags == ["header", "tls"]

    def test_roundtrip_dict(self):
        f = Finding(check_id="tls", title="t", severity="high", url="https://a.com", cwe="CWE-295")
        d = f.to_dict()
        assert d["severity"] == "high"
        assert "fingerprint" in d
        assert Finding.from_dict(d) == f

    def test_group_key_usa_cwe_ou_check(self):
        assert Finding(check_id="a", title="t", cwe="CWE-79", severity="high").group_key == "CWE-79|high"
        assert Finding(check_id="a", title="t", severity="low").group_key == "a|low"


class TestFindingSet:
    def _f(self, check_id="tls", host="a.com", severity="low", path="/x"):
        return Finding(check_id=check_id, title="t", severity=severity, url=f"https://{host}{path}")

    def test_add_retorna_true_para_novo(self):
        s = FindingSet()
        assert s.add(self._f()) is True
        assert len(s) == 1

    def test_deduplica_mesmo_achado(self):
        s = FindingSet()
        s.add(self._f())
        assert s.add(self._f()) is False
        assert len(s) == 1

    def test_deduplica_mesmo_achado_com_query_diferente(self):
        s = FindingSet()
        s.add(Finding(check_id="tls", title="t", url="https://a.com/x?id=1"))
        s.add(Finding(check_id="tls", title="t", url="https://a.com/x?id=2"))
        assert len(s) == 1

    def test_nao_deduplica_hosts_diferentes(self):
        s = FindingSet()
        s.extend([self._f(host="a.com"), self._f(host="b.com")])
        assert len(s) == 2

    def test_extend_conta_novos(self):
        s = FindingSet([self._f()])
        assert s.extend([self._f(), self._f(host="b.com")]) == 1
        assert len(s) == 2

    def test_ordenado_por_severidade_decrescente(self):
        s = FindingSet([self._f(check_id="a", severity="low"), self._f(check_id="b", severity="critical")])
        assert [f.check_id for f in s.sorted()] == ["b", "a"]

    def test_counts_todas_as_severidades(self):
        s = FindingSet([self._f(check_id="a", severity="high"), self._f(check_id="b", host="b.com", severity="info")])
        counts = s.counts()
        assert counts["high"] == 1 and counts["info"] == 1
        assert counts["critical"] == 0 and sum(counts.values()) == 2

    def test_group_by_cwe(self):
        s = FindingSet(
            [
                self._f(check_id="a", host="a.com", severity="high"),
                self._f(check_id="b", host="b.com", severity="high"),
            ]
        )
        groups = s.group_by_cwe()
        assert list(groups) == ["a|high", "b|high"]

    def test_bool_e_iter(self):
        assert not FindingSet()
        s = FindingSet([self._f()])
        assert s and len(list(s)) == 1

    def test_to_list_ordenado(self):
        s = FindingSet([self._f(check_id="a", severity="low"), self._f(check_id="b", host="b.com", severity="critical")])
        assert [d["check_id"] for d in s.to_list()] == ["b", "a"]
