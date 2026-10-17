import time

import pytest
import requests
from requests.adapters import BaseAdapter
from requests.models import Response

from hs.core.http import RateLimiter, SafeClient, ScopeViolation
from hs.core.scope import Scope

BASE = {
    "program": "acme",
    "include": ["example.com"],
    "authorization": {"authorized_by": "sec@acme.test", "reference": "BB-1"},
}


def make_scope(**kw):
    return Scope.from_dict({**BASE, **kw})


class FakeAdapter(BaseAdapter):
    def __init__(self, handler):
        super().__init__()
        self.handler = handler
        self.calls: list[requests.PreparedRequest] = []

    def send(self, request, **kwargs):
        self.calls.append(request)
        return self.handler(request)

    def close(self):
        pass


def make_response(request, status=200, headers=None, body=b"", reason="OK"):
    response = Response()
    response.status_code = status
    response.reason = reason
    response.url = request.url
    response.request = request
    response.raw = type("Raw", (), {"read": lambda self, *a, **k: body, "release_conn": lambda self: None})()
    response.headers.update(headers or {})
    response._content = body
    response.encoding = "utf-8"
    return response


def client_with(handler, scope=None, **kw):
    adapter = FakeAdapter(handler)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    client = SafeClient(
        scope or make_scope(),
        session=session,
        sleep=lambda s: None,
        per_second=0,
        backoff=0.0,
        **kw,
    )
    return client, adapter


def always(response_factory):
    return lambda req: response_factory(req)


class TestScopeGuard:
    def test_permite_requisao_no_escopo(self):
        client, adapter = client_with(always(lambda r: make_response(r)))
        assert client.get("https://example.com/x").status_code == 200
        assert len(adapter.calls) == 1

    def test_get_levanta_fora_do_escopo(self):
        client, _ = client_with(always(lambda r: make_response(r)))
        with pytest.raises(ScopeViolation, match="fora do escopo"):
            client.get("https://evil.com/x")

    def test_try_get_retorna_none_fora_do_escopo(self):
        client, adapter = client_with(always(lambda r: make_response(r)))
        assert client.try_get("https://evil.com/x") is None
        assert adapter.calls == []

    def test_registra_bloqueio_com_motivo(self):
        client, _ = client_with(always(lambda r: make_response(r)))
        client.try_get("https://evil.com/x")
        assert len(client.blocked) == 1
        assert "fora do escopo" in client.blocked[0].error
        assert client.blocked[0].in_scope is False

    def test_resumo_de_bloqueios(self):
        client, _ = client_with(always(lambda r: make_response(r)))
        client.try_get("https://evil.com/a")
        client.try_get("https://outro.com/b")
        summary = client.out_of_scope_summary()
        assert sum(summary.values()) == 2

    def test_excluido_pelo_scope_e_bloqueado(self):
        scope = make_scope(exclude=["admin.example.com"])
        client, adapter = client_with(always(lambda r: make_response(r)), scope=scope)
        assert client.try_get("https://admin.example.com/") is None
        assert adapter.calls == []

    def test_bypass_deixa_passar(self):
        scope = Scope.from_dict(BASE, bypass=True)
        client, _ = client_with(always(lambda r: make_response(r)), scope=scope)
        assert client.get("https://qualquer.com/").status_code == 200


class TestRedirecionamentos:
    def test_segue_redirect_dentro_do_escopo(self):
        client, adapter = client_with(
            lambda r: make_response(r, status=301, headers={"Location": "/final"})
            if r.url.endswith("/old")
            else make_response(r, body=b"final")
        )
        response = client.get("https://example.com/old")
        assert response.status_code == 200
        assert [c.url for c in adapter.calls] == ["https://example.com/old", "https://example.com/final"]

    def test_redirect_para_fora_do_escopo_e_bloqueado(self):
        client, adapter = client_with(
            lambda r: make_response(r, status=302, headers={"Location": "https://evil.com/steal"})
        )
        assert client.try_get("https://example.com/old") is None
        assert [c.url for c in adapter.calls] == ["https://example.com/old"]
        assert client.blocked[-1].error == "fora do escopo autorizado"

    def test_redirecionamento_relativo_e_resolvido(self):
        client, adapter = client_with(
            lambda r: make_response(r, status=302, headers={"Location": "../outro"})
            if "antigo" in r.url
            else make_response(r)
        )
        client.get("https://example.com/dir/antigo")
        assert adapter.calls[-1].url == "https://example.com/outro"

    def test_respeita_limite_de_redirects(self):
        client, _ = client_with(
            always(lambda r: make_response(r, status=302, headers={"Location": "/loop"})),
            max_redirects=2,
        )
        response = client.try_get("https://example.com/a")
        assert response.status_code == 302
        assert "redirecionamentos" in client.exchanges[-1].error

    def test_301_sem_location_encerra(self):
        client, _ = client_with(always(lambda r: make_response(r, status=301)))
        assert client.get("https://example.com/a").status_code == 301


class TestRetries:
    def test_retry_em_429(self):
        calls = {"n": 0}

        def handler(r):
            calls["n"] += 1
            return make_response(r, status=429) if calls["n"] == 1 else make_response(r, body=b"ok")

        client, _ = client_with(handler, retries=2)
        assert client.get("https://example.com/a").status_code == 200
        assert calls["n"] == 2

    def test_retry_em_503_ate_esgotar(self):
        calls = {"n": 0}

        def handler(r):
            calls["n"] += 1
            return make_response(r, status=503)

        client, _ = client_with(handler, retries=2)
        response = client.try_get("https://example.com/a")
        assert response.status_code == 503
        assert calls["n"] == 3

    def test_nao_retry_em_404(self):
        calls = {"n": 0}

        def handler(r):
            calls["n"] += 1
            return make_response(r, status=404)

        client, _ = client_with(handler, retries=3)
        assert client.get("https://example.com/a").status_code == 404
        assert calls["n"] == 1

    def test_retry_em_erro_de_conexao(self):
        calls = {"n": 0}

        def handler(r):
            calls["n"] += 1
            if calls["n"] < 3:
                raise requests.ConnectionError("boom")
            return make_response(r)

        client, _ = client_with(handler, retries=3)
        assert client.get("https://example.com/a").status_code == 200
        assert calls["n"] == 3

    def test_esgotou_retries_registra_erro(self):
        def handler(r):
            raise requests.ConnectionError("sem rota")

        client, _ = client_with(handler, retries=1)
        assert client.try_get("https://example.com/a") is None
        assert "ConnectionError" in client.exchanges[-1].error


class TestCorpoEHeaders:
    def test_trunca_corpo_alem_do_limite(self):
        client, _ = client_with(always(lambda r: make_response(r, body=b"A" * 5000)), max_bytes=1000)
        client.get("https://example.com/a")
        exchange = client.exchanges[-1]
        assert exchange.truncated is True
        assert len(exchange.body_preview) == 1000
        assert exchange.body_len == 5000

    def test_corpo_pequeno_nao_trunca(self):
        client, _ = client_with(always(lambda r: make_response(r, body=b"hello")))
        client.get("https://example.com/a")
        assert client.exchanges[-1].truncated is False
        assert client.exchanges[-1].body_preview == "hello"

    def test_envia_user_agent_padrao(self):
        client, adapter = client_with(always(lambda r: make_response(r)))
        client.get("https://example.com/a")
        assert adapter.calls[0].headers["User-Agent"].startswith("hackersec/")

    def test_user_agent_customizado(self):
        client, adapter = client_with(always(lambda r: make_response(r)), user_agent="meu-scan/1.0")
        client.get("https://example.com/a")
        assert adapter.calls[0].headers["User-Agent"] == "meu-scan/1.0"

    def test_headers_customizados_sao_preservados(self):
        client, adapter = client_with(always(lambda r: make_response(r)))
        client.get("https://example.com/a", headers={"X-Test": "1"})
        assert adapter.calls[0].headers["X-Test"] == "1"

    def test_captura_headers_da_resposta(self):
        client, _ = client_with(always(lambda r: make_response(r, headers={"X-Powered-By": "PHP/8.1"})))
        client.get("https://example.com/a")
        assert client.exchanges[-1].response_headers["X-Powered-By"] == "PHP/8.1"


class TestRateLimiter:
    def test_espaca_requisicoes(self):
        slept: list[float] = []
        limiter = RateLimiter(per_second=10)
        for _ in range(4):
            limiter.acquire(slept.append)
        assert len(slept) >= 1
        assert all(s >= 0 for s in slept)

    def test_zero_desliga_espera(self):
        slept: list[float] = []
        limiter = RateLimiter(per_second=0)
        for _ in range(5):
            limiter.acquire(slept.append)
        assert slept == []

    def test_thread_safe_nao_explode(self):
        import threading

        limiter = RateLimiter(per_second=1000)
        errors: list[Exception] = []

        def worker():
            try:
                for _ in range(50):
                    limiter.acquire(lambda s: None)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


class TestDataSources:
    def test_fonte_de_dados_publica_nao_e_bloqueada_pelo_scope(self):
        client, adapter = client_with(always(lambda r: make_response(r, body=b"[]")))
        assert client.get("https://crt.sh/?q=x").status_code == 200
        assert len(adapter.calls) == 1

    def test_fonte_de_dados_com_query_e_ok(self):
        client, _ = client_with(always(lambda r: make_response(r)))
        assert client.try_get("https://crt.sh/", params={"q": "%.a.com"}) is not None

    def test_hospedeiro_parecido_nao_e_isento(self):
        client, adapter = client_with(always(lambda r: make_response(r)))
        assert client.try_get("https://crt.sh.evil.com/") is None
        assert adapter.calls == []

    def test_fonte_de_dados_customizada(self):
        client, _ = client_with(always(lambda r: make_response(r)), data_sources=["api.osint.test:443"])
        assert client.get("https://api.osint.test/x").status_code == 200

    def test_data_sources_vazio_desliga_isencao(self):
        client, adapter = client_with(always(lambda r: make_response(r)), data_sources=[])
        assert client.try_get("https://crt.sh/") is None
        assert adapter.calls == []

    def test_redirect_de_fonte_para_alvo_e_respeitado(self):
        client, adapter = client_with(
            lambda r: make_response(r, status=302, headers={"Location": "https://example.com/x"})
            if "crt.sh" in r.url
            else make_response(r, body=b"alvo")
        )
        assert client.get("https://crt.sh/").status_code == 200
        assert [c.url for c in adapter.calls] == ["https://crt.sh/", "https://example.com/x"]

    def test_redirect_de_fonte_para_fora_do_escopo_e_bloqueado(self):
        client, adapter = client_with(
            lambda r: make_response(r, status=302, headers={"Location": "https://evil.com/x"})
        )
        assert client.try_get("https://crt.sh/") is None
        assert [c.url for c in adapter.calls] == ["https://crt.sh/"]
        assert client.blocked[-1].error == "fora do escopo autorizado"


class TestCicloDeVida:
    def test_clear_zera_registros(self):
        client, _ = client_with(always(lambda r: make_response(r)))
        client.get("https://example.com/a")
        client.try_get("https://evil.com/a")
        client.clear()
        assert client.exchanges == [] and client.blocked == []

    def test_context_manager(self):
        client, _ = client_with(always(lambda r: make_response(r)))
        with client as c:
            assert c.get("https://example.com/a").status_code == 200

    def test_exchange_to_dict(self):
        client, _ = client_with(always(lambda r: make_response(r)))
        client.get("https://example.com/a")
        data = client.exchanges[-1].to_dict()
        assert data["status"] == 200 and "body_preview" in data
