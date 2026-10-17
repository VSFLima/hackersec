"""Geracao de relatorios de bug bounty em Markdown e HTML.

Entrada: um `FindingSet`. Saida: Markdown no formato HackerOne ou Bugcrowd,
mais um resumo executivo e um dashboard HTML autocontido.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from ..core.models import Asset, Finding, FindingSet, Severity

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

SEVERITY_H1 = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Informative",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def slugify(text: str) -> str:
    keep = [c.lower() if c.isalnum() else "-" for c in (text or "")]
    slug = "".join(keep)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")[:80] or "finding"


def render_index(findings: Sequence[Finding], *, program: str = "") -> str:
    """Indice com links para cada relatorio individual."""
    if not findings:
        return "# Relatorio sem achados\n"
    lines = [f"# Relatorio de Seguranca - {program}" if program else "# Relatorio de Seguranca", ""]
    counts = FindingSet(list(findings)).counts()
    lines.append("| Severidade | Total |")
    lines.append("|---|---|")
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        lines.append(f"| {SEVERITY_H1[severity]} | {counts[severity.value]} |")
    lines += ["", "## Achados", "", "| # | Severidade | Titulo | Alvo | Relatorio |", "|---|---|---|---|---|"]
    for index, finding in enumerate(findings, start=1):
        lines.append(
            f"| {index} | {SEVERITY_H1[finding.severity]} | {_md_cell(finding.title)} "
            f"| {_md_cell(finding.asset or '-')} | [{slugify(finding.check_id)}-{index}]({slugify(finding.check_id)}-{index}.md) |"
        )
    lines += ["", f"_Gerado por hackersec em {now_iso()}._"]
    return "\n".join(lines) + "\n"


def render_hackerone(finding: Finding, *, program: str = "", researcher: str = "") -> str:
    severity = SEVERITY_H1[finding.severity]
    cvss = f" (CVSS {finding.cvss})" if finding.cvss is not None else ""
    parts = [
        f"# {finding.title}",
        "",
        "## Resumo",
        "",
        finding.description or finding.title,
        "",
        "## Classificacao",
        "",
        f"- **Severidade:** {severity}{cvss}",
        f"- **CWE:** {finding.cwe or 'N/A'}",
        f"- **Programa:** {program or 'N/A'}",
        f"- **Alvo:** {finding.asset or 'N/A'}",
        f"- **URL:** {finding.url or 'N/A'}",
    ]
    if finding.cve:
        parts.append(f"- **CVE:** {finding.cve}")
    parts += ["", "## Passos para reproduzir", ""]
    parts += [f"{i}. {step}" for i, step in enumerate(finding.steps, start=1)] or [
        "1. Abrir a URL indicada e observar o comportamento descrito."
    ]
    parts += ["", "## Prova de conceito", "", "```http", f"GET {finding.url or finding.asset} HTTP/1.1", "```", ""]
    if finding.evidence:
        parts += ["### Evidencia", "", "```json", _json_block(finding.evidence), "```", ""]
    parts += [
        "## Impacto",
        "",
        finding.impact or "Pode permitir acesso indevido a informacoes ou acoes nao autorizadas.",
        "",
        "## Correcao",
        "",
        finding.remediation or "Aplicar a configuracao de seguranca recomendada.",
        "",
    ]
    if finding.references:
        parts += ["## Referencias", ""] + [f"- {ref}" for ref in finding.references] + [""]
    if researcher:
        parts += [f"_Reportado por {researcher} em {now_iso()}._"]
    return "\n".join(parts)


def render_bugcrowd(finding: Finding, *, program: str = "", researcher: str = "") -> str:
    severity = SEVERITY_H1[finding.severity]
    parts = [
        f"# {finding.title}",
        "",
        "## Summary",
        "",
        finding.description or finding.title,
        "",
        "## Description",
        "",
        f"Affected asset: `{finding.asset or 'N/A'}`",
        "",
        f"- Severity: **{severity}**",
        f"- Weakness: **{finding.cwe or 'N/A'}**",
        f"- Program: **{program or 'N/A'}**",
        "",
        "## Steps to Reproduce",
        "",
    ]
    parts += [f"{i}. {step}" for i, step in enumerate(finding.steps, start=1)] or [
        "1. Request the affected URL and observe the response described above."
    ]
    parts += [
        "",
        "## Proof of Concept",
        "",
        "```http",
        f"GET {finding.url or finding.asset} HTTP/1.1",
        "```",
        "",
    ]
    if finding.evidence:
        parts += ["## Supporting Material", "", "```json", _json_block(finding.evidence), "```", ""]
    parts += [
        "## Impact",
        "",
        finding.impact or "May allow unauthorized access to data or actions.",
        "",
        "## Remediation",
        "",
        finding.remediation or "Apply the recommended security configuration.",
        "",
    ]
    if finding.references:
        parts += ["## References", ""] + [f"- {ref}" for ref in finding.references] + [""]
    if researcher:
        parts += [f"_Submitted by {researcher} on {now_iso()}._"]
    return "\n".join(parts)


def render_summary(
    findings: Iterable[Finding],
    assets: Sequence[Asset] = (),
    *,
    program: str = "",
    authorization: str = "",
) -> str:
    finding_set = FindingSet(list(findings))
    counts = finding_set.counts()
    lines = [f"# Execucao de Recon - {program}" if program else "# Execucao de Recon", ""]
    if authorization:
        lines += [f"**Autorizacao:** {authorization}", ""]
    lines += [
        "## Numeros",
        "",
        f"- Subdominios/ativos mapeados: **{len(assets)}**",
        f"- Achados unicos: **{len(finding_set)}**",
        f"- Hosts respondendo: **{sum(1 for a in assets if a.is_live)}**",
        "",
        "## Distribuicao por severidade",
        "",
        "| Severidade | Total |",
        "|---|---|",
    ]
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        lines.append(f"| {SEVERITY_H1[severity]} | {counts[severity.value]} |")
    lines.append("")
    if finding_set:
        lines += ["## Top achados", ""]
        for finding in finding_set.sorted()[:10]:
            lines.append(
                f"- {SEVERITY_EMOJI[finding.severity]} **{finding.severity.label}** "
                f"{finding.title} ({finding.asset or 'N/A'})"
            )
        lines.append("")
    if assets:
        lines += ["## Ativos", "", "| Host | Esquema | Status | Titulo | Stack |", "|---|---|---|---|---|"]
        for asset in assets:
            lines.append(
                f"| {_md_cell(asset.host)} | {asset.scheme or '-'} | {asset.status or '-'} "
                f"| {_md_cell(asset.title or '-')} | {_md_cell(', '.join(asset.tech) or '-')} |"
            )
        lines.append("")
    lines.append(f"_Gerado por hackersec em {now_iso()}._")
    return "\n".join(lines)


def render_html(
    findings: Iterable[Finding],
    assets: Sequence[Asset] = (),
    *,
    program: str = "",
    title: str = "Relatorio hackersec",
) -> str:
    finding_set = FindingSet(list(findings))
    counts = finding_set.counts()

    cards = []
    for finding in finding_set.sorted():
        evidence = ""
        if finding.evidence:
            evidence = (
                '<details><summary>Evidencia</summary><pre>'
                + _esc(json.dumps(finding.evidence, indent=2, ensure_ascii=False))
                + "</pre></details>"
            )
        steps = ""
        if finding.steps:
            steps = "<ol>" + "".join(f"<li>{_esc(s)}</li>" for s in finding.steps) + "</ol>"
        cards.append(
            f"""<article class="card sev-{finding.severity.value}" id="{_esc(finding.fingerprint)}">
<div class="card-head"><span class="badge {_esc(finding.severity.value)}">{SEVERITY_H1[finding.severity]}</span>
<span class="cwe">{_esc(finding.cwe or '-')}</span></div>
<h2>{_esc(finding.title)}</h2>
<p class="target">{_esc(finding.asset or '-')}{_esc(' | ' + finding.url if finding.url else '')}</p>
<p>{_esc(finding.description or '')}</p>
{steps}
{f'<p class="impact"><strong>Impacto:</strong> {_esc(finding.impact)}</p>' if finding.impact else ''}
{f'<p><strong>Correcao:</strong> {_esc(finding.remediation)}</p>' if finding.remediation else ''}
{evidence}
</article>"""
        )

    rows = "".join(
        f"<tr><td>{_esc(a.host)}</td><td>{_esc(a.scheme or '-')}</td><td>{a.status or '-'}</td>"
        f"<td>{_esc(a.title or '-')}</td><td>{_esc(', '.join(a.tech) or '-')}</td></tr>"
        for a in assets
    )

    tiles = "".join(
        f'<div class="tile {sev.value}"><span class="n">{counts[sev.value]}</span><span class="l">{SEVERITY_H1[sev]}</span></div>'
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    )

    return f"""<!DOCTYPE html>
<html lang="pt"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<style>
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; padding:2rem 1rem; background:#0d1117; color:#e6edf3;
  font:15px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
.wrap {{ max-width:1100px; margin:0 auto; }}
h1 {{ font-size:1.6rem; margin:0 0 .25rem; }}
.sub {{ color:#8b949e; margin:0 0 1.5rem; font-size:.9rem; }}
.tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(110px,1fr)); gap:.75rem; margin-bottom:2rem; }}
.tile {{ background:#161b22; border:1px solid #30363d; border-left-width:4px; border-radius:8px; padding:.9rem; text-align:center; }}
.tile .n {{ display:block; font-size:1.8rem; font-weight:700; }}
.tile .l {{ display:block; font-size:.72rem; text-transform:uppercase; letter-spacing:.06em; color:#8b949e; }}
.critical {{ border-left-color:#f85149; }} .high {{ border-left-color:#ff7b72; }}
.medium  {{ border-left-color:#d29922; }} .low    {{ border-left-color:#58a6ff; }}
.info    {{ border-left-color:#8b949e; }}
.card {{ background:#161b22; border:1px solid #30363d; border-left-width:4px; border-radius:8px;
  padding:1.1rem 1.3rem; margin-bottom:1rem; }}
.card-head {{ display:flex; gap:.6rem; align-items:center; margin-bottom:.5rem; }}
.badge {{ font-size:.7rem; font-weight:700; text-transform:uppercase; padding:.2rem .5rem; border-radius:4px; color:#0d1117; }}
.badge.critical {{ background:#f85149; }} .badge.high {{ background:#ff7b72; }}
.badge.medium {{ background:#d29922; }} .badge.low {{ background:#58a6ff; }}
.badge.info {{ background:#8b949e; }}
.cwe {{ font-size:.75rem; color:#8b949e; }}
.card h2 {{ font-size:1.05rem; margin:0 0 .35rem; }}
.target {{ font-family:ui-monospace,monospace; font-size:.8rem; color:#79c0ff; margin:0 0 .6rem; word-break:break-all; }}
.impact {{ color:#ffa657; }}
pre {{ background:#0d1117; border:1px solid #30363d; border-radius:6px; padding:.7rem; overflow:auto;
  font-size:.78rem; max-height:340px; }}
details summary {{ cursor:pointer; color:#79c0ff; font-size:.85rem; }}
table {{ width:100%; border-collapse:collapse; margin-top:.5rem; font-size:.85rem; }}
th,td {{ text-align:left; padding:.45rem .6rem; border-bottom:1px solid #21262d; }}
th {{ color:#8b949e; font-size:.75rem; text-transform:uppercase; letter-spacing:.05em; }}
footer {{ color:#8b949e; font-size:.8rem; margin-top:2rem; border-top:1px solid #21262d; padding-top:1rem; }}
</style></head><body><div class="wrap">
<h1>{_esc(title)}</h1>
<p class="sub">Programa: {_esc(program or 'N/A')} &middot; {len(finding_set)} achado(s) &middot; {len(assets)} ativo(s) &middot; {_esc(now_iso())}</p>
<div class="tiles">{tiles}</div>
{"".join(cards) if cards else "<p>Nenhum achado.</p>"}
{f'<h2>Ativos mapeados</h2><table><thead><tr><th>Host</th><th>Esquema</th><th>Status</th><th>Titulo</th><th>Stack</th></tr></thead><tbody>{rows}</tbody></table>' if assets else ''}
<footer>Gerado por hackersec. Achados deduplicados por fingerprint estavel.</footer>
</div></body></html>"""


def render_all(
    findings: Iterable[Finding],
    assets: Sequence[Asset] = (),
    *,
    program: str = "",
    authorization: str = "",
    platform: str = "hackerone",
    researcher: str = "",
) -> dict[str, str]:
    """Dicionario nome -> conteudo, pronto a gravar em disco."""
    ordered = FindingSet(list(findings)).sorted()
    renderer = render_bugcrowd if platform == "bugcrowd" else render_hackerone
    out: dict[str, Any] = {
        "00-index.md": render_index(ordered, program=program),
        "01-summary.md": render_summary(ordered, assets, program=program, authorization=authorization),
        "report.html": render_html(ordered, assets, program=program, title=f"Relatorio - {program or 'pentest'}"),
        "findings.json": json.dumps(
            {"program": program, "generated_at": now_iso(), "findings": [f.to_dict() for f in ordered]},
            indent=2,
            ensure_ascii=False,
        ),
    }
    for index, finding in enumerate(ordered, start=1):
        out[f"reports/{slugify(finding.check_id)}-{index}.md"] = renderer(
            finding, program=program, researcher=researcher
        )
    return out


def _esc(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _md_cell(value: str) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def _json_block(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)
