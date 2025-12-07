# modules/report.py
# -*- coding: utf-8 -*-
"""
Cyber Threat Intelligent — Module report
Objectif : Générateur de rapport HTML (incluant l'analyse LLM si fournie)

Développeur : Lahat Fall (UQAC) — Projet-stage en cybersécurité défensive.
© 2025, Tous droits réservés.
"""
from __future__ import annotations

import html
from typing import Iterable


def _li(items: Iterable[str]) -> str:
    """Transforme une liste de chaînes en <li> triés et dédoublonnés."""
    items = [html.escape(str(x)) for x in (items or []) if str(x).strip()]
    return "".join(f"<li>{x}</li>" for x in sorted(set(items))) or "<i>—</i>"


def build_html_report(
    platform: str,
    author: str,
    alert_meta: dict,
    tech_ids: list[str],
    incident_iri: str,
    actions: list[str],
    techniques: list[str],
    llm_text: str | None = None,
    llm_model: str | None = None,
) -> str:
    """
    Génère un rapport HTML autonome.

    - platform        : nom de la plateforme (ex. Cyber Threat Intelligent)
    - author          : auteur du rapport
    - alert_meta      : métadonnées de l’alerte (timestamp, rule.id, agent.name…)
    - tech_ids        : techniques MITRE extraites de l’alerte
    - incident_iri    : IRI de l’incident sélectionné
    - actions         : actions VERIS associées à l’incident
    - techniques      : techniques MITRE associées à l’incident
    - llm_text        : texte d’analyse généré par le LLM (optionnel)
    - llm_model       : nom du modèle LLM (optionnel)
    """
    plat = html.escape(platform or "")
    auth = html.escape(author or "")
    inc = html.escape(incident_iri or "")
    ts = html.escape((alert_meta or {}).get("timestamp", "—"))
    ag = html.escape((alert_meta or {}).get("agent.name", "—"))
    rid = html.escape((alert_meta or {}).get("rule.id", "—"))
    mitre = " ".join(html.escape(t) for t in (tech_ids or [])) or "—"

    metrics_html = f"""
    <div class=\"metrics\">
      <div class=\"metric\">
        <span>Techniques extraites</span>
        <strong>{len(tech_ids or [])}</strong>
      </div>
      <div class=\"metric\">
        <span>Techniques incident</span>
        <strong>{len(techniques or [])}</strong>
      </div>
      <div class=\"metric\">
        <span>Actions VERIS</span>
        <strong>{len(actions or [])}</strong>
      </div>
    </div>
    """

    llm_block = """
    <div class=\"card\">
      <h3>Analyse LLM</h3>
      <p class=\"llm-meta\">Aucune analyse n’a été générée.</p>
    </div>
    """
    if llm_text and llm_text.strip():
        llm_block = f"""
        <div class=\"card\">
          <h3>Analyse LLM</h3>
          <p class=\"llm-meta\">Modèle&nbsp;: {html.escape(llm_model or 'N/A')}</p>
          <pre class=\"llm-text\">{html.escape(llm_text.strip())}</pre>
        </div>
        """

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{plat} — Rapport</title>
  <style>
  body {{
    font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    background: #0f111a;
    color: #e5e7eb;
    margin: 24px;
  }}
  .header {{
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 18px;
  }}
  .header img {{
    border-radius: 12px;
  }}
  .header-title {{
    font-size: 1.8rem;
    font-weight: 700;
  }}
  .header-sub {{
    font-size: 0.95rem;
    color: #9ca3af;
  }}
  .card {{
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 12px;
    padding: 16px;
    margin: 10px 0;
  }}
  h1, h2, h3 {{
    margin: .35rem 0;
  }}
  small {{
    color: #9ca3af;
  }}
  a {{
    color: #93c5fd;
    text-decoration: none;
  }}
  .metrics {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin: 12px 0 24px 0;
  }}
  .metric {{
    flex: 1;
    min-width: 160px;
    background: #101a29;
    border: 1px solid #1f2937;
    border-radius: 10px;
    padding: 12px;
  }}
  .metric span {{
    font-size: .85rem;
    color: #9ca3af;
  }}
  .metric strong {{
    display: block;
    font-size: 1.6rem;
    margin-top: 4px;
  }}
  .detail-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
  }}
  .detail-grid .card {{
    margin: 0;
  }}
  .llm-meta {{
    color: #9ca3af;
    font-size: .9rem;
    margin: 0 0 6px 0;
  }}
  .llm-text {{
    white-space: pre-wrap;
    word-wrap: break-word;
    background: #0b1220;
    border: 1px solid #1f2937;
    border-radius: 10px;
    padding: 12px;
    margin: 0;
  }}
  @media print {{
    body {{
      background: #fff;
      color: #111;
    }}
    .card {{
      border: 1px solid #999;
    }}
    .llm-text {{
      background: #f6f8fa !important;
      color: #111 !important;
    }}
  }}
  </style>
</head>
<body>

  <div class="header">
    <img src="logo.jpeg" alt="Cyber Threat Intelligent" width="80">
    <div>
      <div class="header-title">Cyber Threat Intelligent</div>
      <div class="header-sub">Lahat Fall (UQAC) — Rapport d'analyse</div>
    </div>
  </div>

  <h1>{plat} — Rapport d'analyse</h1>
  <p><b>Auteur&nbsp;:</b> {auth} — © 2025</p>

  {metrics_html}

  <div class="detail-grid">
    <div class="card">
      <h3>Alerte</h3>
      <p>
        <b>Timestamp&nbsp;:</b> {ts}<br/>
        <b>Agent&nbsp;:</b> {ag}<br/>
        <b>Rule ID&nbsp;:</b> {rid}<br/>
        <b>MITRE (extraits)&nbsp;:</b> {mitre}
      </p>
    </div>

    <div class="card">
      <h3>Incident</h3>
      <p><b>IRI&nbsp;:</b> {inc}</p>
    </div>
  </div>

  <div class="card">
    <h3>Techniques (MITRE)</h3>
    <ul>{_li(techniques)}</ul>
  </div>

  <div class="card">
    <h3>Actions (VERIS)</h3>
    <ul>{_li(actions)}</ul>
  </div>

  {llm_block}

  <p style="margin-top:24px;font-size:.85rem;color:#9ca3af">
    Développé et signé par <b>Lahat Fall</b> — UQAC.
  </p>

</body>
</html>"""
