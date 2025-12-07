# -*- coding: utf-8 -*-
"""
Intellisec-Analyst — Module ui_components
Objectif: Branding/CSS/headers/footers

Développeur : Lahat Fall (UQAC) — Projet-stage en cybersécurité défensive.
© 2025, Tous droits réservés.
"""
from __future__ import annotations

import logging

import streamlit as st

logger = logging.getLogger(__name__)


def inject_branding_header(version: str = "v1.0") -> None:
    """Injecte le bandeau supérieur (branding + CSS global)."""
    st.markdown(
        f"""
<style>
.block-container {{
  padding-top: 1rem;
  padding-bottom: 2rem;
}}
.cti-header {{
  position: sticky;
  top: 0;
  z-index: 9999;
  background: linear-gradient(90deg, #0f111a 0%, #0b1220 100%);
  border-bottom: 1px solid #1f2937;
  padding: .75rem 1rem;
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: .75rem;
}}
.cti-title {{
  font-weight: 700;
  font-size: 1.15rem;
  letter-spacing: .3px;
  color: #e5e7eb;
  margin: 0;
}}
.cti-sub {{
  color: #9ca3af;
  font-size: .85rem;
  margin: 0;
}}
.cti-badge {{
  background: #22c55e1a;
  color: #22c55e;
  border: 1px solid #22c55e55;
  padding: .25rem .5rem;
  border-radius: .5rem;
  font-size: .75rem;
  white-space: nowrap;
}}
.cti-grid {{
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: .75rem;
}}
@media (max-width: 1200px) {{
  .cti-grid {{ grid-template-columns: repeat(3, 1fr); }}
}}
@media (max-width: 900px) {{
  .cti-grid {{ grid-template-columns: repeat(2, 1fr); }}
}}
@media (max-width: 600px) {{
  .cti-grid {{ grid-template-columns: 1fr; }}
}}
.cti-card {{
  background: #111827;
  border: 1px solid #1f2937;
  border-radius: .75rem;
  padding: 1rem;
  height: 100%;
}}
.cti-card h4 {{
  margin: .25rem 0 .5rem;
  font-size: 1rem;
}}
.cti-footer {{
  color: #9ca3af;
  font-size: .8rem;
  text-align: center;
  padding-top: 1rem;
  border-top: 1px dashed #263042;
}}
</style>
<div class="cti-header">
  <div>
    <h1 class="cti-title">Cyber Threat Intelligent</h1>
    <p class="cti-sub">
      Plate-forme MITRE ↔ VERIS ↔ VCDB
      <b>Développée par LAHAT FALL (UQAC)</b>
    </p>
  </div>
  <div class="cti-badge">{version} • © 2025 Lahat Fall</div>
</div>
""",
        unsafe_allow_html=True,
    )


def footer_signature() -> None:
    """Ajoute une signature cohérente pour la partie basse de l'application."""
    st.markdown(
        """
<div class="cti-footer">
  Intellisec-Analyst — © 2025 <b>Lahat Fall</b>, UQAC. Tous droits réservés.
</div>
""",
        unsafe_allow_html=True,
    )
