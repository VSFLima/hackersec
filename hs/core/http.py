"""Cliente HTTP seguro.

Propriedades garantidas pela camada de transporte:

- toda requisicao e validada contra o escopo antes de sair
- redirecionamentos sao seguidos manualmente hop a hop, cada um revalidado
- rate limit por intervalo minimo entre requisicoes (thread-safe)
- retry com backoff apenas para 429/5xx e erros de conexao
- corpo de resposta truncado em `max_bytes`
- todo request/response fica registrado para servir de evidencia
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import BaseAdapter

DEFAULT_UA = "hackersec/0.1 (+https://github.com/authorized-testing)"
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
DEFAULT_DATA_SOURCES = frozenset({"crt.sh", "crt.sh:443"})


class ScopeViolation(Exception):
    """Requisicao bloqueada por estar fora do escopo autorizado."""


@dataclass
class Exchange:
    """Registro de um request/response, usado como evidencia no relatorio."""

    url: str
    method: str = "GET"
    status: int | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    body_preview: str = ""
    body_len: int = 0
    truncated: bool = False
    elapsed_ms: int = 0
    redirects: list[str] = field(default_factory=list)
    error: str = ""
    in_scope: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "status": self.status,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "body_preview": self.body_preview,
            "body_len": self.body_len,
            "truncated": self.truncated,
            "elapsed_ms": self.elapsed_ms,
            "redirects": self.redirects,
            "error": self.error,
        }


class RateLimiter:
    """Espacamento minimo entre o inicio de cada requisicao."""

    def __init__(self, per_second: float) -> None:
        self.interval = 0.0 if per_second <= 0 else 1.0 / float(per_second)
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def acquire(self, sleep: Callable[[float], None] = time.sleep) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            if wait > 0:
                sleep(wait)
                now = time.monotonic()
            self._next_allowed = now + self.interval


class SafeClient:
    def __init__(
        self,
        scope,
        *,
        per_second: float = 10.0,
        timeout: float = 10.0,
        max_bytes: int = 2_000_000,
        max_redirects: int = 5,
        retries: int = 2,
        backoff: float = 0.5,
        user_agent: str = DEFAULT_UA,
        verify: bool = True,
        data_sources: Iterable[str] | None = None,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.scope = scope
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.retries = retries
        self.backoff = backoff
        self.user_agent = user_agent
        self.verify = verify
        self.data_sources = {
            _authority(d) for d in (data_sources if data_sources is not None else DEFAULT_DATA_SOURCES)
        }
        self.limiter = RateLimiter(per_second)
        self.session = session or requests.Session()
        self._sleep = sleep
        self.exchanges: list[Exchange] = []
        self.blocked: list[Exchange] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------- interface

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        """Requisicao que levanta `ScopeViolation` se estiver fora do escopo."""
        response = self._send("GET", url, **kwargs)
        if response is None:
            raise ScopeViolation(f"fora do escopo: {url}")
        return response

    def try_get(self, url: str, **kwargs: Any) -> requests.Response | None:
        """Mesma coisa, mas retorna None em vez de levantar."""
        return self._send("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response | None:
        return self._send("HEAD", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response | None:
        return self._send(method.upper(), url, **kwargs)

    # ---------------------------------------------------------------- interno

    def _send(self, method: str, url: str, **kwargs: Any) -> requests.Response | None:
        current = url
        exchange = Exchange(url=url, method=method)

        for hop in range(self.max_redirects + 1):
            if not self._is_data_source(current):
                decision = self.scope.check(current)
                if not decision.allowed:
                    exchange.in_scope = False
                    exchange.error = decision.reason
                    self._record(exchange, blocked=True)
                    return None

            response = self._single(method, current, exchange, **kwargs)
            if response is None:
                self._record(exchange)
                return None

            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if not location:
                    self._record(exchange)
                    return response
                if hop >= self.max_redirects:
                    exchange.error = "limite de redirecionamentos excedido"
                    self._record(exchange)
                    return response
                nxt = urljoin(current, location)
                exchange.redirects.append(nxt)
                current = nxt
                continue

            self._record(exchange)
            return response

        self._record(exchange)
        return None

    def _single(
        self, method: str, url: str, exchange: Exchange, **kwargs: Any
    ) -> requests.Response | None:
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        headers.update(kwargs.pop("headers", None) or {})
        allow_redirects = kwargs.pop("allow_redirects", False)
        verify = kwargs.pop("verify", self.verify)
        timeout = kwargs.pop("timeout", self.timeout)
        stream = kwargs.pop("stream", False)

        last_error = ""
        for attempt in range(self.retries + 1):
            self.limiter.acquire(self._sleep)
            started = time.monotonic()
            try:
                response = self.session.request(
                    method,
                    url,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    verify=verify,
                    timeout=timeout,
                    stream=stream,
                    **kwargs,
                )
            except requests.RequestException as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < self.retries:
                    self._sleep(self.backoff * (2**attempt))
                    continue
                exchange.error = last_error
                exchange.elapsed_ms = int((time.monotonic() - started) * 1000)
                return None

            exchange.elapsed_ms = int((time.monotonic() - started) * 1000)
            exchange.status = response.status_code
            exchange.request_headers = dict(headers)
            exchange.response_headers = {k: v for k, v in response.headers.items()}

            if response.status_code in RETRY_STATUS and attempt < self.retries:
                self._sleep(self.backoff * (2**attempt))
                continue

            if not stream and response.content is not None:
                self._absorb_body(exchange, response)
            return response

        exchange.error = last_error or "retries esgotados"
        return None

    def _absorb_body(self, exchange: Exchange, response: requests.Response) -> None:
        raw = response.content or b""
        if len(raw) > self.max_bytes:
            exchange.truncated = True
            raw = raw[: self.max_bytes]
        exchange.body_len = len(response.content or b"")
        try:
            exchange.body_preview = raw.decode(response.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            exchange.body_preview = raw.decode("utf-8", errors="replace")

    def _is_data_source(self, url: str) -> bool:
        """Fontes de dados publicas nao passam pelo escopo do alvo."""
        if not self.data_sources:
            return False
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return f"{host}:{port}" in self.data_sources or host in self.data_sources

    def _record(self, exchange: Exchange, *, blocked: bool = False) -> None:
        with self._lock:
            (self.blocked if blocked else self.exchanges).append(exchange)

    def clear(self) -> None:
        with self._lock:
            self.exchanges.clear()
            self.blocked.clear()

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "SafeClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def out_of_scope_summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for exchange in self.blocked:
            counts[exchange.error] = counts.get(exchange.error, 0) + 1
        return counts


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _authority(host: str) -> str:
    text = (host or "").strip().lower()
    if "/" in text:
        text = text.split("/", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if ":" in text and not text.startswith("["):
        return text
    return f"{text}:443"
