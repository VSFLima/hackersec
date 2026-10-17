"""CLI do hackersec."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core.http import SafeClient
from .core.models import FindingSet
from .core.scope import Scope, ScopeError
from .engine import Engine, RunResult
from .report.render import render_all

BANNER = "hackersec - pentest e bug bounty com scope enforcement"

SCOPE_TEMPLATE = """\
# scope.yaml - alvos explicitamente autorizados.
# Nada fora de 'include' sera testado. 'exclude' tem precedencia.

program: "{program}"

# Dominios, subdominios (wildcard), IPs ou CIDRs.
# Exemplo: "*.example.com", "10.0.0.0/8", "api.example.com:8443"
include:
  - "example.com"
  - "*.example.com"

# Nunca testar, mesmo que case com include.
exclude:
  - "admin.example.com"

# Portas liberadas para teste.
allowed_ports: [80, 443, 8080, 8443]

# Extensoes nunca requisitadas (fuzzing de diretorio gera muito falso-positivo).
deny_extensions: [".png", ".jpg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2"]

# Obrigatorio: sem isto a ferramenta recusa correr.
authorization:
  authorized_by: "seu.email@empresa.com"
  reference: "ID-do-programa-ou-contrato"
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hackersec", description=BANNER)
    parser.add_argument("--version", action="store_true", help="mostra a versao e sai")
    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="cria um scope.yaml de exemplo")
    p_init.add_argument("-o", "--out", default="scope.yaml")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--scope", help="caminho do scope.yaml (obrigatorio)")
    common.add_argument(
        "--no-scope",
        action="store_true",
        help="DESLIGA a validacao de escopo. Use apenas em laboratorio/CTF com autorizacao propria.",
    )
    common.add_argument("--rate", type=float, default=10.0, help="requisicoes por segundo")
    common.add_argument("--timeout", type=float, default=10.0)
    common.add_argument("--insecure", action="store_true", help="nao validar certificado TLS")
    common.add_argument("-o", "--out", default="out", help="diretorio de saida")
    common.add_argument("--researcher", default="", help="nome para assinar o relatorio")

    p_recon = sub.add_parser("recon", parents=[common], help="recon completo de um programa")
    p_recon.add_argument("target", nargs="+", help="dominio-raiz autorizado")
    p_recon.add_argument("--no-ct", action="store_true", help="pular certificate transparency")
    p_recon.add_argument("--no-probe", action="store_true", help="so passivo, sem tocar no alvo")
    p_recon.add_argument("--no-surface", action="store_true", help="pular auditoria de superficie")
    p_recon.add_argument("--workers", type=int, default=10)

    p_audit = sub.add_parser("audit", parents=[common], help="audita a superficie web de uma URL")
    p_audit.add_argument("url")

    p_secrets = sub.add_parser("secrets", parents=[common], help="procura segredos em codigo/JS")
    p_secrets.add_argument("path", help="arquivo ou diretorio")
    p_secrets.add_argument("--no-generic", action="store_true", help="desligar detector de baixa confianca")

    return parser


def load_scope_for(args: argparse.Namespace) -> Scope:
    if getattr(args, "no_scope", False):
        return Scope.from_dict({"program": "unscoped-lab"}, bypass=True)
    if not getattr(args, "scope", None):
        raise ScopeError(
            "escopo obrigatorio: use --scope scope.yaml. "
            "Em laboratorio/CTF com autorizacao propria use --no-scope."
        )
    return Scope.from_file(args.scope)


def make_engine(scope: Scope, args: argparse.Namespace) -> Engine:
    client = SafeClient(
        scope,
        per_second=getattr(args, "rate", 10.0),
        timeout=getattr(args, "timeout", 10.0),
        verify=not getattr(args, "insecure", False),
    )
    return Engine(scope, client=client)


def write_reports(result: RunResult, scope: Scope, out_dir: str, platform: str, researcher: str) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = render_all(
        result.findings,
        result.assets,
        program=scope.program,
        authorization=f"{scope.authorized_by} ({scope.authorization_ref})" if scope.authorized_by else "",
        platform=platform,
        researcher=researcher,
    )
    for name, content in files.items():
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    result_path = out / "run.json"
    result_path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def print_summary(result: RunResult, out: Path) -> None:
    counts = result.findings.counts()
    print(f"\nativos: {len(result.assets)}  achados: {len(result.findings)}  duracao: {result.duration_s:.1f}s")
    print("  " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    for finding in result.findings.sorted()[:10]:
        print(f"  [{finding.severity.value:8}] {finding.title} ({finding.asset or '-'})")
    for note in result.notes:
        print(f"  ! {note}")
    if result.blocked:
        print(f"  {len(result.blocked)} requisicao(oes) bloqueada(s) por estar fora do escopo")
    print(f"  relatorio: {out}/report.html  (indice: {out}/00-index.md)")


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.out)
    if path.exists():
        print(f"scope.yaml ja existe em {path}", file=sys.stderr)
        return 1
    path.write_text(SCOPE_TEMPLATE.format(program="meu-programa"), encoding="utf-8")
    print(f"criado {path} - preencha 'include' e 'authorization' antes de usar")
    return 0


def cmd_recon(args: argparse.Namespace) -> int:
    scope = load_scope_for(args)
    with make_engine(scope, args) as engine:
        result = engine.run_recon(
            args.target,
            use_ct=not args.no_ct,
            do_probe=not args.no_probe,
            do_surface=not args.no_surface,
            workers=args.workers,
        )
    out = write_reports(result, scope, args.out, "hackerone", args.researcher)
    print_summary(result, out)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    scope = load_scope_for(args)
    with make_engine(scope, args) as engine:
        findings = engine.audit_url(args.url)
    result = RunResult(program=scope.program, findings=FindingSet(findings))
    out = write_reports(result, scope, args.out, "hackerone", args.researcher)
    print_summary(result, out)
    return 0 if findings else 2


def cmd_secrets(args: argparse.Namespace) -> int:
    scope = load_scope_for(args)
    with make_engine(scope, args) as engine:
        findings = engine.scan_source(args.path, allow_generic=not args.no_generic)
    result = RunResult(program=scope.program, findings=FindingSet(findings))
    out = write_reports(result, scope, args.out, "hackerone", args.researcher)
    print_summary(result, out)
    return 0 if findings else 2


def main(argv: list[str] | None = None) -> int:
    from . import __version__

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"hackersec {__version__}")
        return 0
    if not args.command:
        parser.print_help()
        return 1

    handlers = {"init": cmd_init, "recon": cmd_recon, "audit": cmd_audit, "secrets": cmd_secrets}
    try:
        return handlers[args.command](args)
    except ScopeError as exc:
        print(f"erro de escopo: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrompido", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
