"""Deteccao de segredos em texto, JavaScript, mapas e arquivos de config.

Padroes de alta confianca (chaves com formato proprio) e um detector generico
de atribuicoes com filtro de entropia e lista de placeholders.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Pattern

from ..core.models import Finding, Severity

MIN_GENERIC_LENGTH = 12
MIN_ENTROPY = 3.2
PLACEHOLDER_MARKERS = (
    "EXAMPLE",
    "XXXX",
    "YYYYYY",
    "ZZZZZZ",
    "CHANGEME",
    "CHANGE_ME",
    "TESTKEY",
    "TESTSECRET",
    "DUMMY",
    "FAKEKEY",
    "SAMPLEKEY",
    "AAAAAAA",
    "1234567",
    "ABCDEFG",
    "ABCDEFGHIJKLMNOP",
)

PLACEHOLDER_TOKENS = (
    "example",
    "changeme",
    "change-me",
    "your_",
    "your-",
    "xxxx",
    "placeholder",
    "dummy",
    "sample",
    "todo",
    "fixme",
    "insert_",
    "replace",
    "abcdef",
    "123456",
    "redacted",
    "notreal",
    "fake",
    "test_key",
    "my_key",
)

ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z0-9_.\-]*(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|auth[_-]?key|private[_-]?key|client[_-]?secret)[A-Za-z0-9_.\-]*)
    \s*[:=]\s*
    ["'](?P<value>[^"'\n]{%d,})["']
    """
    % MIN_GENERIC_LENGTH
)

URL_CREDENTIALS_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@")

JS_QUOTE = "'\\\"`"
JS_PATH_BODY = r"(?:api|v\d|rest|graphql|auth|oauth|admin|internal|ws)[A-Za-z0-9_\-./{}:$]*"
JS_ENDPOINT_RE = re.compile(r"[" + JS_QUOTE + r"](?P<p>/" + JS_PATH_BODY + r")[" + JS_QUOTE + r"]")
JS_ABSOLUTE_URL_RE = re.compile(
    r"[" + JS_QUOTE + r"](?P<u>https?://[A-Za-z0-9.\-]+\.[A-Za-z]{2,}[A-Za-z0-9_\-./{}:$?&=]*)[" + JS_QUOTE + r"]"
)


@dataclass(frozen=True)
class SecretPattern:
    pattern_id: str
    name: str
    regex: Pattern[str]
    severity: Severity
    cwe: str
    confidence: str = "high"
    guidance: str = ""


PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("aws-access-key-id", "AWS Access Key ID", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})\b"), Severity.CRITICAL, "CWE-798", guidance="Revogue a chave no IAM e rotacione imediatamente."),
    SecretPattern("aws-secret-access-key", "AWS Secret Access Key", re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?(?P<v>[A-Za-z0-9/+=]{40})"), Severity.CRITICAL, "CWE-798", guidance="Revogue o par de chaves no IAM."),
    SecretPattern("google-api-key", "Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), Severity.HIGH, "CWE-798", guidance="Restrinja a chave por API, dominio e IP no Google Cloud Console."),
    SecretPattern("google-oauth-client", "Google OAuth Client ID", re.compile(r"\b(\d{10,}-[0-9a-z]{20,}\.apps\.googleusercontent\.com)\b"), Severity.INFO, "CWE-200", guidance="Client ID nao e segredo, mas revela a projecao configurada."),
    SecretPattern("slack-token", "Slack Token", re.compile(r"\b(xox[baprse]-[0-9A-Za-z\-]{10,})"), Severity.HIGH, "CWE-798", guidance="Revogue o token no Slack e gere um novo."),
    SecretPattern("slack-webhook", "Slack Webhook", re.compile(r"(hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,})"), Severity.HIGH, "CWE-798", guidance="Revogue o webhook e restrinja o canal de destino."),
    SecretPattern("stripe-secret", "Stripe Secret Key", re.compile(r"\b(sk_live_[0-9A-Za-z]{20,})"), Severity.CRITICAL, "CWE-798", guidance="Revogue a chave no painel do Stripe."),
    SecretPattern("github-pat", "GitHub Personal Access Token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})"), Severity.CRITICAL, "CWE-798", guidance="Revogue o token em Settings > Developer settings."),
    SecretPattern("github-fine-grained-pat", "GitHub Fine-grained PAT", re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,})"), Severity.CRITICAL, "CWE-798", guidance="Revogue o token no GitHub."),
    SecretPattern("npm-token", "npm Token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), Severity.HIGH, "CWE-798", guidance="Revogue o token no npm e regenere."),
    SecretPattern("sendgrid-key", "SendGrid API Key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})"), Severity.CRITICAL, "CWE-798", guidance="Revogue a chave no SendGrid."),
    SecretPattern("mailgun-key", "Mailgun API Key", re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"), Severity.HIGH, "CWE-798"),
    SecretPattern("twilio-key", "Twilio API Key", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), Severity.HIGH, "CWE-798"),
    SecretPattern("private-key-block", "Bloco de chave privada", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"), Severity.CRITICAL, "CWE-798", guidance="A chave foi publicada: substitua o par de chaves imediatamente."),
    SecretPattern("jwt-token", "JWT hardcoded", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"), Severity.MEDIUM, "CWE-798", confidence="medium", guidance="JWT com longa validade no cliente; prefira emissao curta."),
    SecretPattern("firebase-db", "URL de Firebase Realtime DB", re.compile(r"\b([a-z0-9\-]+\.firebaseio\.com)\b"), Severity.MEDIUM, "CWE-200", confidence="medium", guidance="Verifique as regras de leitura do banco."),
    SecretPattern("open-bucket", "Bucket S3 publico", re.compile(r"\b([a-z0-9][a-z0-9.\-]{2,}\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com)\b"), Severity.LOW, "CWE-200", confidence="medium", guidance="Confirme se o bucket permite listagem/leitura anonima."),
)


@dataclass(frozen=True)
class Match:
    pattern_id: str
    name: str
    value: str
    severity: Severity
    cwe: str
    confidence: str
    line: int
    column: int
    masked: str
    source: str = "conteudo"
    guidance: str = ""

    def to_finding(self, *, asset: str = "") -> Finding:
        source = self.source
        return Finding(
            check_id=f"secret-{self.pattern_id}",
            title=f"{self.name} exposto em {source}",
            severity=self.severity,
            cwe=self.cwe,
            description=(
                f"Foi encontrado um valor com o formato de {self.name} em {source} "
                f"(linha {self.line}, coluna {self.column}). Valor mascarado: {self.masked}."
            ),
            impact="Credenciais expostas em codigo ou no bundle do navegador permitem acesso nao autorizado ao servico correspondente.",
            steps=[
                f"Abrir {source} e ir ate a linha {self.line}.",
                f"Confirmar que o valor {self.masked} e uma credencial valida.",
                "Verificar o historico do repositorio: o segredo pode estar em commits antigos.",
            ],
            evidence={"pattern": self.pattern_id, "masked_value": self.masked, "line": self.line, "source": source},
            remediation=self.guidance or "Revogue/rotacione a credencial e mova-a para um cofre de segredos ou variaveis de ambiente.",
            asset=asset or source,
            source="hackersec",
            confidence=self.confidence,
            tags=["secret", "exposure"],
        )


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_placeholder(value: str) -> bool:
    """Filtro agressivo, usado apenas no detector generico."""
    low = value.lower()
    if any(token in low for token in PLACEHOLDER_TOKENS):
        return True
    if "<" in value or ">" in value or "${" in value or "{{" in value:
        return True
    if value.lower() in {"null", "none", "true", "false", "undefined", "changeme", "secret", "password"}:
        return True
    return len(set(low)) <= 3


def is_documented_placeholder(value: str) -> bool:
    """Filtro conservador para padroes de formato proprio.

    Rejeita apenas marcadores que nunca ocorrem numa credencial real
    (ex.: a chave de exemplo da documentacao da AWS).
    """
    upper = (value or "").upper()
    if not upper:
        return True
    if any(marker in upper for marker in PLACEHOLDER_MARKERS):
        return True
    if "<" in value or ">" in value or "${" in value or "{{" in value:
        return True
    if len(set(upper)) <= 3:
        return True
    return False


def mask(value: str, keep: int = 4) -> str:
    text = value.strip()
    if len(text) <= keep * 2:
        return "*" * len(text)
    return f"{text[:keep]}{'*' * (len(text) - keep * 2)}{text[-keep:]}"


def line_of(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last_break = text.rfind("\n", 0, index)
    column = index - last_break
    return line, column


def _captured_value(found: re.Match[str]) -> str:
    """Valor capturado pelo padrao: primeiro grupo nomeado, depois numerado, senao a match."""
    named = found.groupdict().get("v")
    if named:
        return named
    for index in range(1, (found.re.groups or 0) + 1):
        try:
            captured = found.group(index)
        except (IndexError, re.error):
            continue
        if captured:
            return captured
    return found.group(0)


def _captured_start(found: re.Match[str]) -> int:
    """Offset do valor capturado, com fallback para o inicio da match."""
    named = found.groupdict()
    if "v" in named and found.start("v") >= 0:
        return found.start("v")
    for index in range(1, (found.re.groups or 0) + 1):
        try:
            if found.start(index) >= 0:
                return found.start(index)
        except (IndexError, re.error):
            continue
    return found.start()


def scan_secrets(text: str, *, source: str = "conteudo", allow_generic: bool = True) -> list[Match]:
    """Varre texto e devolve as credenciais encontradas, sem duplicar valor+posicao."""
    matches: list[Match] = []
    seen: set[tuple[str, int, int]] = set()

    for spec in PATTERNS:
        for found in spec.regex.finditer(text or ""):
            value = _captured_value(found)
            if not value or is_documented_placeholder(value):
                continue
            line, column = line_of(text, _captured_start(found))
            key = (spec.pattern_id, line, column)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                Match(
                    pattern_id=spec.pattern_id,
                    name=spec.name,
                    value=value,
                    severity=spec.severity,
                    cwe=spec.cwe,
                    confidence=spec.confidence,
                    line=line,
                    column=column,
                    masked=mask(value),
                    source=source,
                    guidance=spec.guidance,
                )
            )

    if allow_generic:
        for found in ASSIGNMENT_RE.finditer(text or ""):
            value = found.group("value")
            if is_placeholder(value) or shannon_entropy(value) < MIN_ENTROPY:
                continue
            line, column = line_of(text, found.start("value"))
            name = found.group("name")
            specific = _matches_specific(value)
            if specific and specific != name:
                continue
            matches.append(
                Match(
                    pattern_id="generic-api-key",
                    name=f"Possivel segredo em '{name}'",
                    value=value,
                    severity=Severity.MEDIUM,
                    cwe="CWE-798",
                    confidence="low",
                    line=line,
                    column=column,
                    masked=mask(value),
                    source=source,
                )
            )

    for found in URL_CREDENTIALS_RE.finditer(text or ""):
        if is_placeholder(found.group(0)):
            continue
        line, column = line_of(text, found.start())
        matches.append(
            Match(
                pattern_id="url-embedded-credentials",
                name="Credenciais em URL",
                value=found.group(0),
                severity=Severity.HIGH,
                cwe="CWE-798",
                confidence="high",
                line=line,
                column=column,
                masked=mask(found.group(0)),
                source=source,
                guidance="Mova as credenciais para variaveis de ambiente ou um cofre de segredos.",
            )
        )

    return sorted(matches, key=lambda m: (m.line, m.column, m.pattern_id))


def _matches_specific(value: str) -> str:
    for spec in PATTERNS:
        if spec.regex.search(value):
            return spec.name
    return ""


def extract_js_endpoints(text: str) -> list[str]:
    """Extrai endpoints e URLs referenciados no bundle JS."""
    found: dict[str, None] = {}
    for match in JS_ENDPOINT_RE.finditer(text or ""):
        found.setdefault(match.group("p"), None)
    for match in JS_ABSOLUTE_URL_RE.finditer(text or ""):
        found.setdefault(match.group("u"), None)
    return sorted(found)


SKIPPED_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"})
TEXT_SUFFIXES = frozenset(
    {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json", ".env", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".py", ".php", ".rb", ".go", ".txt", ".html", ".htm", ".xml", ".properties", ".sh"}
)


def iter_source_files(root: str | Path) -> Iterator[Path]:
    base = Path(root)
    if base.is_file():
        yield base
        return
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIPPED_DIRS for part in path.parts):
            continue
        if path.name.startswith(".env") or path.suffix.lower() in TEXT_SUFFIXES:
            yield path


def scan_path(root: str | Path, *, allow_generic: bool = True, max_files: int = 5000) -> list[Match]:
    """Varre um ficheiro ou diretorio e devolve todos os segredos encontrados."""
    matches: list[Match] = []
    count = 0
    for path in iter_source_files(root):
        if count >= max_files:
            break
        count += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        matches.extend(scan_secrets(text, source=str(path), allow_generic=allow_generic))
    return matches


def to_findings(matches: Iterable[Match]) -> list[Finding]:
    """Converte a lista de matches em findings deduplicaveis."""
    return [m.to_finding() for m in matches]
