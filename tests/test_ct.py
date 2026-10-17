import pytest

from hs.core.scope import Scope
from hs.recon.ct import CTResult, enumerate_ct, in_root_domain, is_valid_hostname, merge_hosts, parse_crtsh

SCOPE = Scope.from_dict(
    {
        "program": "acme",
        "include": ["example.com", "*.example.com"],
        "exclude": ["admin.example.com"],
        "authorization": {"authorized_by": "sec@acme.test", "reference": "BB-1"},
    }
)

PAYLOAD = """[
  {"name_value": "www.example.com\\napi.example.com", "common_name": "www.example.com"},
  {"name_value": "*.dev.example.com", "common_name": "dev.example.com"},
  {"name_value": "example.com", "common_name": "example.com"},
  {"name_value": "outro.com\\nwww.example.com", "common_name": "outro.com"},
  {"name_value": "_dmarc.example.com", "common_name": "_dmarc.example.com"},
  {"name_value": "*.example.com", "common_name": "example.com"},
  {"name_value": "", "common_name": ""}
]"""


class TestIsValidHostname:
    @pytest.mark.parametrize(
        "host", ["example.com", "a.b.example.com", "x1-y2.example.co.uk", "localhost.localdomain"]
    )
    def test_aceita(self, host):
        assert is_valid_hostname(host)

    @pytest.mark.parametrize(
        "host",
        ["", "  ", "*.example.com", "example", "_dmarc.example.com", "localhost", "exa mple.com", "a" * 300],
    )
    def test_rejeita(self, host):
        assert not is_valid_hostname(host)

    def test_normaliza_caixa_e_ponto_final(self):
        assert is_valid_hostname("WWW.Example.COM.")


class TestParseCrtsh:
    def test_extrai_hosts(self):
        result = parse_crtsh(PAYLOAD)
        assert "www.example.com" in result.hosts
        assert "api.example.com" in result.hosts
        assert "dev.example.com" in result.hosts
        assert "example.com" in result.hosts

    def test_remove_wildcard_do_prefixo(self):
        result = parse_crtsh(PAYLOAD)
        assert not any(h.startswith("*") for h in result.hosts)

    def test_mantem_tudo_quando_root_nao_e_informado(self):
        assert "outro.com" in parse_crtsh(PAYLOAD).hosts

    def test_descarta_fora_do_dominio_quando_root_informado(self):
        result = parse_crtsh(PAYLOAD, root="example.com")
        assert "outro.com" not in result.hosts
        assert "www.example.com" in result.hosts

    def test_root_nao_casa_com_dominio_similar(self):
        assert parse_crtsh(PAYLOAD, root="ample.com").hosts == []

    def test_descarta_underscore(self):
        assert "_dmarc.example.com" not in parse_crtsh(PAYLOAD).hosts

    def test_deduplica(self):
        result = parse_crtsh(PAYLOAD)
        assert result.hosts == sorted(set(result.hosts))
        assert result.hosts.count("www.example.com") == 1

    def test_ordena_alfabeticamente(self):
        assert parse_crtsh(PAYLOAD).hosts == sorted(parse_crtsh(PAYLOAD).hosts)

    def test_conta_brutos_e_filtrados(self):
        result = parse_crtsh(PAYLOAD)
        assert result.raw_entries > len(result.hosts)
        assert result.filtered_out == result.raw_entries - len(result.hosts)

    def test_aceita_lista_de_dicts(self):
        result = parse_crtsh([{"name_value": "a.example.com"}])
        assert result.hosts == ["a.example.com"]

    def test_aceita_string_vazia(self):
        assert parse_crtsh("").hosts == []

    def test_ignora_entradas_nao_dict(self):
        assert parse_crtsh(["lixo", None, {"name_value": "a.example.com"}]).hosts == ["a.example.com"]


class TestCTResultAsAssets:
    def test_so_gera_assets_autorizados(self):
        result = CTResult(hosts=["a.example.com", "evil.com", "admin.example.com"], raw_entries=3, filtered_out=0)
        assets = result.as_assets(SCOPE)
        assert [a.host for a in assets] == ["a.example.com"]

    def test_registra_a_fonte(self):
        asset = CTResult(hosts=["a.example.com"], raw_entries=1, filtered_out=0).as_assets(SCOPE)[0]
        assert asset.sources == ["crt.sh"]


class TestInRootDomain:
    @pytest.mark.parametrize("host", ["example.com", "www.example.com", "a.b.example.com"])
    def test_aceita(self, host):
        assert in_root_domain(host, "example.com")

    @pytest.mark.parametrize("host", ["outro.com", "example.com.evil.com", "notexample.com", "ample.com"])
    def test_rejeita(self, host):
        assert not in_root_domain(host, "example.com")

    def test_entrada_vazia(self):
        assert not in_root_domain("", "example.com")
        assert not in_root_domain("example.com", "")


class TestMergeHosts:
    def test_une_deduplica_e_normaliza(self):
        assert merge_hosts(["A.com", "a.com.", "*.b.com"], ["b.com", "c.com"]) == ["a.com", "b.com", "c.com"]

    def test_aceita_grupos_vazios(self):
        assert merge_hosts([], None, []) == []


class TestEnumerateCT:
    def test_consulta_e_filtra_pelo_scope(self):
        import requests
        from requests.adapters import BaseAdapter
        from requests.models import Response

        from hs.core.http import SafeClient

        class Adapter(BaseAdapter):
            def send(self, request, **kw):
                r = Response()
                r.status_code = 200
                r.url = request.url
                r.request = request
                r.headers = {}
                r._content = PAYLOAD.encode()
                r.encoding = "utf-8"
                r.raw = type("R", (), {"read": lambda s, *a, **k: b"", "release_conn": lambda s: None})()
                return r

            def close(self):
                pass

        session = requests.Session()
        session.mount("https://", Adapter())
        client = SafeClient(SCOPE, session=session, per_second=0)
        result = enumerate_ct("example.com", client, SCOPE)
        assert "www.example.com" in result.hosts
        assert "outro.com" not in result.hosts
        assert "admin.example.com" not in result.hosts

    def test_dominio_fora_do_scope_nao_gera_trafego(self):
        class NoNetwork:
            def request(self, *a, **k):
                raise AssertionError("nao deveria requisir crt.sh")

        from hs.core.http import SafeClient

        client = SafeClient(SCOPE, session=NoNetwork(), per_second=0)
        assert enumerate_ct("evil.com", client, SCOPE).hosts == []

    def test_resposta_nao_200_vazia_resultado(self):
        import requests
        from requests.adapters import BaseAdapter
        from requests.models import Response

        from hs.core.http import SafeClient

        class Adapter(BaseAdapter):
            def send(self, request, **kw):
                r = Response()
                r.status_code = 503
                r.url = request.url
                r.request = request
                r.headers = {}
                r._content = b""
                r.raw = type("R", (), {"read": lambda s, *a, **k: b"", "release_conn": lambda s: None})()
                return r

            def close(self):
                pass

        session = requests.Session()
        session.mount("https://", Adapter())
        client = SafeClient(SCOPE, session=session, per_second=0)
        assert enumerate_ct("example.com", client, SCOPE).hosts == []
