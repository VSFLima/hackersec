import pytest
import requests
from requests.adapters import BaseAdapter
from requests.models import Response

from hs.core.http import SafeClient
from hs.core.scope import Scope
from hs.recon.probe import detect_tech, extract_title, probe_all, probe_host

SCOPE = Scope.from_dict(
    {
        "program": "acme",
        "include": ["example.com", "*.example.com"],
        "authorization": {"authorized_by": "sec@acme.test", "reference": "BB-1"},
    }
)


class FakeAdapter(BaseAdapter):
    def __init__(self, handler):
        super().__init__()
        self.handler = {k.rstrip("/"): v for k, v in handler.items()}
        self.calls: list[str] = []

    def send(self, request, **kwargs):
        self.calls.append(request.url)
        entry = self.handler.get(request.url.rstrip("/"))
        if entry is None:
            raise requests.ConnectionError("sem rota")
        status, headers, body = entry
        r = Response()
        r.status_code = status
        r.url = request.url
        r.request = request
        r.headers = dict(headers or {})
        r._content = body.encode() if isinstance(body, str) else body
        r.encoding = "utf-8"
        r.raw = type("R", (), {"read": lambda s, *a, **k: b"", "release_conn": lambda s: None})()
        return r

    def close(self):
        pass


def client_with(handler):
    adapter = FakeAdapter(handler)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return SafeClient(SCOPE, session=session, per_second=0, retries=0), adapter


class TestExtractTitle:
    @pytest.mark.parametrize(
        "body,expected",
        [
            ("<html><head><title>Login</title></head></html>", "Login"),
            ("<TITLE>  spaced  out  </TITLE>", "spaced out"),
            ("<title>Multi\nline</title>", "Multi line"),
            ("<html>sem title</html>", ""),
            ("", ""),
        ],
    )
    def test_extrai(self, body, expected):
        assert extract_title(body) == expected

    def test_trunca_em_300(self):
        assert len(extract_title(f"<title>{'a' * 1000}</title>")) == 300


class TestDetectTech:
    def test_detecta_por_header(self):
        assert "nginx" in detect_tech({"Server": "nginx/1.24"}, "")

    def test_detecta_cloudflare(self):
        assert "cloudflare" in detect_tech({"Server": "cloudflare"}, "")

    def test_detecta_por_body(self):
        assert "wordpress" in detect_tech({}, '<link href="/wp-content/themes/x">')

    def test_detecta_next(self):
        assert "react" in detect_tech({}, '<script id="__NEXT_DATA__">')

    def test_nao_detecta_em_pagina_vazia(self):
        assert detect_tech({}, "") == []

    def test_resultado_ordenado_e_sem_repeticao(self):
        tech = detect_tech({"Server": "nginx"}, "<script id='__NEXT_DATA__'>")
        assert tech == sorted(set(tech))
        assert "nginx" in tech and "react" in tech


class TestProbeHost:
    def test_detecta_host_vivo_com_https(self):
        client, _ = client_with({"https://a.example.com": (200, {"Server": "nginx"}, "<title>A</title>")})
        asset = probe_host(client, "a.example.com")
        assert asset is not None
        assert asset.is_live and asset.status == 200
        assert asset.scheme == "https" and asset.title == "A"
        assert "nginx" in asset.tech

    def test_fallback_para_http(self):
        client, _ = client_with({"http://a.example.com": (200, {}, "ok")})
        asset = probe_host(client, "a.example.com")
        assert asset.scheme == "http"

    def test_host_morto_retorna_none(self):
        client, _ = client_with({})
        assert probe_host(client, "morto.example.com") is None

    def test_fora_do_scope_nao_gera_trafego(self):
        client, adapter = client_with({"https://evil.com": (200, {}, "ok")})
        assert probe_host(client, "evil.com") is None
        assert adapter.calls == []

    def test_403_ainda_conta_como_vivo(self):
        client, _ = client_with({"https://a.example.com": (403, {}, "forbidden")})
        asset = probe_host(client, "a.example.com")
        assert asset.is_live and asset.status == 403

    def test_registra_fonte_probe(self):
        client, _ = client_with({"https://a.example.com": (200, {}, "ok")})
        assert probe_host(client, "a.example.com").sources == ["probe"]


class TestProbeAll:
    def test_devolve_apenas_vivos_ordenados(self):
        client, _ = client_with(
            {
                "https://b.example.com": (200, {}, "b"),
                "https://a.example.com": (200, {}, "a"),
            }
        )
        assets = probe_all(client, ["b.example.com", "a.example.com", "morto.example.com"])
        assert [a.host for a in assets] == ["a.example.com", "b.example.com"]

    def test_deduplica_entrada(self):
        client, adapter = client_with({"https://a.example.com": (200, {}, "a")})
        probe_all(client, ["a.example.com", "A.EXAMPLE.COM", "a.example.com."])
        assert adapter.calls == ["https://a.example.com/"]

    def test_entrada_vazia(self):
        client, _ = client_with({})
        assert probe_all(client, []) == []
