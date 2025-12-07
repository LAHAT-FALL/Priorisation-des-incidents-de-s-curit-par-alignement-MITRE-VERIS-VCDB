#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ruff: noqa: E501
"""
Intellisec-Analyst — Application Streamlit
Corrélation Alerte Wazuh → MITRE ATT&CK → VERIS → VCDB + Analyse LLM + Rapport

Développeur : Lahat Fall (UQAC) — Projet-stage en cybersécurité défensive.
© 2025 — Tous droits réservés.
"""

from __future__ import annotations

import base64
import json
import logging
from html import escape
from inspect import cleandoc
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st
import yaml
from modules.alerts import (
    extract_alert_metadata,
    extract_all_alerts_metadata,
    extract_tech_ids_universal,
    load_wazuh_alerts_any,
)
from modules.llm import build_prompt, call_ollama
from modules.ontology import (
    actions_for_incident,
    actions_to_tech_pairs,
    deduce_incident_techs,
    get_incidents_by_tech,
    lastfrag,
    techniques_for_incident,
)
from modules.rag import SimpleRAG
from modules.report import build_html_report
from modules.ui_components import footer_signature, inject_branding_header
from modules.visuals import draw_chain_enriched
from modules.wazuh_api import WazuhClient
from rdflib import Graph, URIRef
from rdflib.namespace import RDFS

# ===============================
#   Config & Logging
# ===============================
st.set_page_config(page_title="Cyber Threat Intelligent — Lahat Fall (UQAC)", layout="wide")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cti")

inject_branding_header("v1.0")  # Bannière d’en-tête

GLOBAL_STYLES = """
<style>
:root {
    --cti-bg: #050912;
    --cti-panel: #0e1627;
    --cti-card: #111b2d;
    --cti-border: #1f2d3f;
    --cti-brand: #6efacc;
}
html, body, [data-testid="stAppViewContainer"] {
    background: var(--cti-bg);
}
.main .block-container {
    padding-top: 0 !important;
    padding-bottom: 3rem;
    max-width: 1200px;
    margin: 0 auto;
}
[data-testid="stSidebar"] {
    background: #040a16;
    border-right: 1px solid var(--cti-border);
}
[data-testid="stSidebar"] * {
    color: #e2e8f0 !important;
}
.cti-hero {
    display: flex;
    gap: 1.5rem;
    align-items: center;
    border-radius: 1.25rem;
    padding: 1.75rem;
    border: 1px solid var(--cti-border);
    background: radial-gradient(circle at 20% 20%, rgba(21,44,74,0.9), rgba(7,11,20,0.95));
    box-shadow: 0 30px 60px rgba(0,0,0,0.4);
    margin-bottom: 1.5rem;
}
.cti-hero__logo-badge {
    width: 120px;
    height: 120px;
    flex-shrink: 0;
    border-radius: 1.25rem;
    background: radial-gradient(circle at 30% 20%, #1fe4ba, #028090 70%);
    border: 1px solid rgba(255,255,255,0.18);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 20px 50px rgba(0,0,0,0.55);
    overflow: hidden;
}
.cti-hero__logo-badge img {
    width: 96px;
    height: 96px;
    object-fit: cover;
    border-radius: 1rem;
    border: 1px solid rgba(255,255,255,0.3);
    box-shadow: inset 0 0 15px rgba(0,0,0,0.35);
}
.cti-hero__logo-badge span {
    font-size: 1.65rem;
    font-weight: 700;
    color: #fff;
    text-align: center;
    line-height: 1.1;
}
.cti-hero__tag {
    display: inline-flex;
    padding: .35rem .85rem;
    border-radius: 999px;
    font-size: .8rem;
    letter-spacing: .08em;
    text-transform: uppercase;
    background: #1e2238;
    color: #9ad6ff;
    border: 1px solid #2f3c5c;
    margin-bottom: .4rem;
}
.cti-hero__desc {
    color: #c7d2fe;
    margin: 0 0 .4rem;
}
.cti-hero h1 {
    margin: 0 0 .35rem;
    font-size: 2rem;
    color: #f8fafc;
}
.cti-hero__stats {
    display: flex;
    flex-wrap: wrap;
    gap: .5rem;
    margin-top: .85rem;
}
.cti-pill {
    display: inline-flex;
    align-items: center;
    gap: .35rem;
    padding: .35rem .95rem;
    border-radius: 999px;
    background: #ffffff12;
    border: 1px solid #ffffff22;
    font-size: .85rem;
    color: #d6e4ff;
}
.cti-pill--stat {
    padding: .45rem 1rem;
    background: rgba(4,10,22,0.45);
    border-color: rgba(255,255,255,0.15);
    font-weight: 600;
}
.cti-pill__icon {
    font-size: 1rem;
    line-height: 1;
}
.cti-pill.is-off {
    background: #2f1824;
    border-color: #f8717133;
    color: #fecdd3;
}
@media (max-width: 800px) {
    .cti-hero { flex-direction: column; text-align: center; }
    .cti-hero__logo img { width: 72px; height: 72px; }
}
.cti-grid {
    margin-top: 1rem;
    gap: 1rem;
}
.cti-card {
    background: var(--cti-card);
    border: 1px solid var(--cti-border);
    box-shadow: 0 12px 30px rgba(0,0,0,0.35);
}
.cti-card h4 { color: #e2e8f0; }
.cti-card p, .cti-card li { color: #cbd5f5; }
.dashboard-kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: .75rem;
    margin: 1rem 0 1.5rem;
}
.dash-kpi {
    background: linear-gradient(135deg, rgba(28,39,70,0.95), rgba(9,14,30,0.95));
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 1rem;
    padding: .9rem 1.1rem;
    display: flex;
    align-items: center;
    gap: .75rem;
    box-shadow: 0 18px 35px rgba(0,0,0,0.35);
}
.dash-kpi__icon {
    font-size: 1.5rem;
    line-height: 1;
}
.dash-kpi small {
    text-transform: uppercase;
    letter-spacing: .08em;
    color: #8ba0c7;
    font-size: .75rem;
}
.dash-kpi strong {
    display: block;
    color: #f8fafc;
    font-size: 1.35rem;
}
.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
}
.dash-card {
    background: #0c1524;
    border: 1px solid #1f2d3f;
    border-radius: 1.25rem;
    padding: 1.25rem;
    box-shadow: 0 18px 45px rgba(0,0,0,0.35);
}
.dash-card--primary {
    grid-column: span 2;
    background: radial-gradient(circle at 20% 20%, rgba(23,44,74,0.9), rgba(4,8,18,0.95));
    border-color: rgba(110,250,204,0.2);
}
.dash-card--wide { grid-column: span 2; }
@media (max-width: 1100px) {
    .dash-card--primary,
    .dash-card--wide {
        grid-column: span 1;
    }
}
.dash-card__header {
    display: flex;
    flex-direction: column;
    gap: .35rem;
}
.dash-card__header h3 {
    margin: 0;
    color: #f8fafc;
}
.dash-card__subtitle {
    margin: 0;
    color: #c0d3ff;
    line-height: 1.4;
}
.dash-meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: .75rem;
    margin-top: 1rem;
}
.dash-meta {
    background: rgba(0,0,0,0.2);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: .85rem;
    padding: .85rem;
}
.dash-meta span {
    text-transform: uppercase;
    letter-spacing: .08em;
    font-size: .72rem;
    color: #8ba0c7;
}
.dash-meta strong {
    display: block;
    font-size: 1.1rem;
    margin-top: .2rem;
    color: #f8fafc;
}
.dash-meta small {
    color: #9caecf;
    font-size: .8rem;
}
.dash-chipline {
    display: flex;
    flex-wrap: wrap;
    gap: .35rem;
    margin-top: .35rem;
}
.dash-block {
    margin-bottom: .9rem;
}
.dash-block small {
    display: block;
    color: #8ba0c7;
    text-transform: uppercase;
    letter-spacing: .08em;
    font-size: .78rem;
}
.dash-chip {
    display: inline-flex;
    align-items: center;
    padding: .32rem .85rem;
    border-radius: .85rem;
    border: 1px solid rgba(255,255,255,0.18);
    background: rgba(255,255,255,0.05);
    color: #e5edff;
    font-size: .85rem;
}
.dash-chip.is-empty { opacity: .4; }
.dash-list {
    list-style: none;
    padding: 0;
    margin: 0 0 .85rem;
    display: flex;
    flex-direction: column;
    gap: .35rem;
}
.dash-list li {
    display: flex;
    justify-content: space-between;
    gap: .5rem;
    background: #0f1b30;
    border: 1px solid #1e2c42;
    border-radius: .75rem;
    padding: .6rem .85rem;
}
.dash-list span {
    color: #8ba0c7;
    font-size: .8rem;
    text-transform: uppercase;
    letter-spacing: .08em;
}
.dash-list strong {
    color: #f8fafc;
    font-weight: 600;
}
.dash-http-table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: .75rem;
}
.dash-http-table th,
.dash-http-table td {
    border-bottom: 1px solid rgba(255,255,255,0.06);
    padding: .5rem .35rem;
    text-align: left;
    color: #d6e4ff;
}
.dash-http-table th {
    width: 160px;
    color: #8ba0c7;
    font-size: .82rem;
    text-transform: uppercase;
    letter-spacing: .08em;
}
.dash-pre-block small {
    display: block;
    color: #8ba0c7;
    text-transform: uppercase;
    font-size: .75rem;
    letter-spacing: .08em;
    margin-bottom: .2rem;
}
.dash-pre {
    background: #020812;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: .65rem;
    padding: .75rem .9rem;
    margin-bottom: .85rem;
    font-family: "JetBrains Mono", "SFMono-Regular", Consolas, monospace;
    font-size: .85rem;
    color: #c4d7ff;
    overflow-x: auto;
}
.details-panel {
    background: #0b1424;
    border: 1px solid var(--cti-border);
    border-radius: 1.25rem;
    padding: 1.25rem;
    box-shadow: 0 20px 50px rgba(0,0,0,0.35);
    margin-bottom: 1rem;
}
.details-meta {
    display: flex;
    flex-direction: column;
    gap: .4rem;
}
.details-meta code {
    background: rgba(110,250,204,0.08);
    border: 1px solid rgba(110,250,204,0.4);
    padding: .45rem .75rem;
    border-radius: .65rem;
    color: #a6ffde;
    font-size: .9rem;
}
.details-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px,1fr));
    gap: .75rem;
    margin-top: 1rem;
}
.details-card {
    background: #0f1c33;
    border: 1px solid #1f2d3f;
    border-radius: .85rem;
    padding: .9rem 1rem;
}
.details-card span {
    font-size: .8rem;
    color: #8ba0c7;
    text-transform: uppercase;
    letter-spacing: .08em;
}
.details-card strong {
    display: block;
    font-size: 1.5rem;
    color: #f8fafc;
}
.cti-chip-group { margin: 1rem 0; }
.cti-chip-title {
    font-size: .85rem;
    text-transform: uppercase;
    letter-spacing: .12em;
    color: #8ba0c7;
    margin-bottom: .25rem;
}
.cti-chip {
    display: inline-flex;
    align-items: center;
    padding: .35rem .85rem;
    border-radius: .8rem;
    border: 1px solid rgba(255,255,255,0.12);
    background: rgba(255,255,255,0.05);
    color: #e5edff;
    margin: .2rem .25rem .2rem 0;
    font-size: .88rem;
}
.cti-chip.is-empty { opacity: 0.5; }
.panel-title {
    font-weight: 600;
    font-size: 1.05rem;
    margin-bottom: .5rem;
    color: #e5edff;
}
.doc-container {
    background: #090f1c;
    border: 1px solid var(--cti-border);
    border-radius: 1.5rem;
    padding: 2rem;
    box-shadow: 0 35px 65px rgba(0,0,0,0.45);
    display: flex;
    flex-direction: column;
    gap: 1.8rem;
}
.doc-section h2 {
    font-size: 1.45rem;
    margin-bottom: .65rem;
    color: #e2e8f0;
}
.doc-section h3 {
    font-size: 1.2rem;
    margin: 1rem 0 .4rem;
    color: #cbd5f5;
}
.doc-section p {
    margin: .35rem 0;
    color: #c9d4f4;
    line-height: 1.55;
}
.doc-list {
    margin: .35rem 0 .75rem 1rem;
}
.doc-list li {
    color: #d0dbff;
    margin-bottom: .2rem;
}
.doc-divider {
    height: 1px;
    width: 100%;
    background: radial-gradient(circle, rgba(255,255,255,0.2), transparent);
    border: none;
}
.auto-context {
    background: #0b1526;
    border: 1px solid var(--cti-border);
    border-radius: .85rem;
    padding: 1rem 1.1rem;
    color: #d7e4ff;
    font-size: .9rem;
    line-height: 1.5;
    box-shadow: inset 0 0 0 1px rgba(255,255,255,0.02);
}
.auto-context strong { color: var(--cti-brand); }
.auto-context small { color: #94a3b8; }
.stTextArea textarea {
    background: #0b1220;
    border-radius: .85rem !important;
    color: #e5edf9 !important;
    border: 1px solid #1f2d3f !important;
}
.stTabs [role="tablist"] {
    gap: .35rem;
    border-bottom: 1px solid var(--cti-border);
    padding-bottom: .3rem;
    margin-bottom: 1.5rem;
}
.stTabs [role="tab"] {
    padding: .6rem 1rem;
    border-radius: .65rem;
    background: #0f172a;
    border: 1px solid transparent;
    color: #94a3b8;
    font-weight: 500;
}
.stTabs [role="tab"][aria-selected="true"] {
    background: #13233e;
    border-color: #1dd1a1;
    color: var(--cti-brand);
}
.stTabs [role="tab"]:hover {
    border-color: #2f3c5c;
    color: #cbd5f5;
}
.stDownloadButton>button,
.stButton>button {
    border-radius: .65rem;
}
.stButton>button {
    border: 1px solid #1dd1a1;
    background: #0d2822;
    color: #bfffe1;
}
.stButton>button:hover {
    background: #124236;
}
@media (max-width: 880px) {
    .dashboard-kpis {
        grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    }
    .dash-card {
        grid-column: span 1 !important;
        padding: 1rem;
    }
    .details-panel,
    .doc-container {
        padding: 1rem;
    }
    .details-grid {
        grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    }
    .panel-title {
        text-align: center;
    }
}
@media (max-width: 640px) {
    .dashboard-kpis {
        grid-template-columns: 1fr;
    }
    .cti-hero__stats {
        flex-direction: column;
        width: 100%;
    }
    .cti-hero__logo-badge {
        width: 100%;
        max-width: 180px;
        margin: 0 auto;
    }
    .doc-container,
    .details-panel {
        padding: .9rem;
    }
    .panel-title {
        font-size: .95rem;
    }
}
</style>
"""
st.markdown(GLOBAL_STYLES, unsafe_allow_html=True)

LOGO_PATH = Path("assets/logo.jpeg")
def _load_logo_base64(path: Path) -> str:
    try:
        return base64.b64encode(path.read_bytes()).decode("utf-8")
    except Exception:
        return ""

LOGO_B64 = _load_logo_base64(LOGO_PATH)
LABEL_CACHE: Dict[str, str] = {}

DOC_SECTIONS_DATA = [
    {
        "title": "1. Contexte et objectif",
        "html": cleandoc("""
        <div class="doc-section">
            <h2>1. Contexte et objectif</h2>
            <p>Cette plateforme fournit une corrélation <strong>interprétable</strong> entre des alertes SOC issues de Wazuh et des incidents cyber réels.</p>
            <p>Elle repose sur une ontologie OWL qui unifie trois référentiels :</p>
            <ul class="doc-list">
                <li><strong>MITRE ATT&amp;CK</strong> — techniques d’attaque (TTP)</li>
                <li><strong>VERIS</strong> — actions et variétés observées dans les incidents</li>
                <li><strong>VCDB</strong> — incidents historiques documentés</li>
            </ul>
            <p>Chaîne logique visée :</p>
            <p><strong>Alerte → Techniques MITRE → Actions VERIS → Incident</strong></p>
        </div>
        """),
        "rag": "La plateforme CTI corrèle des alertes SOC Wazuh avec des incidents VCDB via une ontologie unifiant MITRE ATT&CK et VERIS afin de justifier la chaîne Alerte → Techniques → Actions → Incident."
    },
    {
        "title": "2. Architecture générale",
        "html": cleandoc("""
        <div class="doc-section">
            <h2>2. Architecture générale</h2>
            <p>La solution est organisée en quatre couches :</p>
            <h3>2.1 Ingestion des alertes</h3>
            <ul class="doc-list">
                <li>Fichiers JSON / NDJSON ou API REST Wazuh</li>
                <li>Extraction des T-IDs via champs structurés et analyse textuelle</li>
                <li>Normalisation (T1059.001 → T1059_001)</li>
            </ul>
            <h3>2.2 Ontologie OWL</h3>
            <p>Modélisation explicite des relations Techniques ↔ Actions ↔ Incidents. L’ontologie est la source unique de vérité.</p>
            <h3>2.3 Moteur de corrélation</h3>
            <p>Interrogations SPARQL / RDF pour récupérer incidents, actions et techniques cohérents avec l’alerte.</p>
            <h3>2.4 Couche d’interprétation</h3>
            <p>Le LLM local lit les relations établies et fournit l’explication SOC.</p>
        </div>
        """),
        "rag": "L’architecture comporte quatre couches : ingestion d’alertes (JSON/NDJSON/API) et normalisation des T-IDs, ontologie OWL comme source unique, moteur de corrélation SPARQL, puis interprétation par LLM local."
    },
    {
        "title": "3. Ontologie OWL : modélisation",
        "html": cleandoc("""
        <div class="doc-section">
            <h2>3. Ontologie OWL : modélisation</h2>
            <h3>3.1 Classes principales</h3>
            <ul class="doc-list">
                <li><code>mitre:Technique</code></li>
                <li><code>veris:Action</code></li>
                <li><code>veris:Incident</code></li>
            </ul>
            <h3>3.2 Relations clés</h3>
            <p><strong>bridge:hasAction :</strong> Incident → Actions VERIS</p>
            <p><strong>bridge:relatesToTechnique :</strong> Action VERIS → Technique MITRE</p>
            <p><strong>bridge:involvesTechnique :</strong> déduit (hasAction ∘ relatesToTechnique)</p>
        </div>
        """),
        "rag": "L’ontologie relie les classes mitre:Technique, veris:Action et veris:Incident via les propriétés bridge:hasAction et bridge:relatesToTechnique, permettant de déduire bridge:involvesTechnique."
    },
    {
        "title": "4. Méthodologie de traitement",
        "html": cleandoc("""
        <div class="doc-section">
            <h2>4. Méthodologie de traitement</h2>
            <ol class="doc-list">
                <li>Extraction MITRE depuis l’alerte</li>
                <li>Interrogation ontologique</li>
                <li>Sélection des incidents compatibles</li>
                <li>Classement par recouvrement d’actions VERIS</li>
                <li>Interprétation par LLM (sans influence sur la corrélation)</li>
            </ol>
        </div>
        """),
        "rag": "Le workflow comporte cinq étapes : extraire les T-IDs, interroger l’ontologie, filtrer les incidents compatibles, les classer via les actions VERIS couvertes, puis produire l’explication par LLM sans influencer la corrélation."
    },
    {
        "title": "5. Visualisation",
        "html": cleandoc("""
        <div class="doc-section">
            <h2>5. Visualisation</h2>
            <p>Deux vues complémentaires :</p>
            <ul class="doc-list">
                <li>Liste complète des actions VERIS</li>
                <li>Chaîne sémantique filtrée par les techniques détectées</li>
            </ul>
        </div>
        """),
        "rag": "La visualisation combine la liste des actions VERIS de l’incident et une chaîne sémantique centrée sur les techniques de l’alerte pour justifier la corrélation."
    },
    {
        "title": "6. Rôle du modèle de langage",
        "html": cleandoc("""
        <div class="doc-section">
            <h2>6. Rôle du modèle de langage</h2>
            <p>Le LLM :</p>
            <ul class="doc-list">
                <li>n’effectue aucune détection ni scoring</li>
                <li>ne modifie pas l’ontologie</li>
                <li>produit uniquement un texte d’explication</li>
            </ul>
        </div>
        """),
        "rag": "Le LLM agit uniquement comme couche d’interprétation textuelle : aucune détection ni scoring, il explique la chaîne sémantique sans altérer la base de connaissance."
    },
    {
        "title": "7. Apport scientifique & limites",
        "html": cleandoc("""
        <div class="doc-section">
            <h2>7. Apport scientifique &amp; limites</h2>
            <h3>Contributions</h3>
            <ul class="doc-list">
                <li>Unification formelle MITRE ↔ VERIS ↔ VCDB</li>
                <li>Usage opérationnel d’une ontologie OWL</li>
                <li>Séparation stricte logique / interprétation</li>
            </ul>
            <h3>Limites</h3>
            <ul class="doc-list">
                <li>Qualité dépendante du mapping MITRE/VERIS</li>
                <li>Traitement d’une alerte à la fois</li>
                <li>Pas d’analyse temporelle</li>
            </ul>
        </div>
        """),
        "rag": "Les apports: unification MITRE-VERIS-VCDB, exploitation OWL opérationnelle et séparation logique/interprétation. Limites: dépendance au mapping, mono-alerte, pas d’analyse temporelle."
    },
    {
        "title": "8. Perspectives",
        "html": cleandoc("""
        <div class="doc-section">
            <h2>8. Perspectives</h2>
            <ul class="doc-list">
                <li>Ajout des mitigations MITRE (lien vers contre-mesures)</li>
                <li>Intégration des tactiques (TAxxxx)</li>
                <li>Couplage à des ontologies défensives</li>
                <li>Support multi-alertes et chronologie</li>
                <li>Enrichissement métier (criticité, actif, impact)</li>
            </ul>
        </div>
        """),
        "rag": "Les perspectives couvrent l’ajout des mitigations, des tactiques, le couplage à des ontologies défensives, la corrélation multi-alertes et l’enrichissement métier."
    },
    {
        "title": "9. Cadre académique",
        "html": cleandoc("""
        <div class="doc-section">
            <h2>9. Cadre académique</h2>
            <p><strong>Étudiant :</strong> Lahat Fall</p>
            <p><strong>Encadrant :</strong> Pr. Jonathan Roy</p>
            <p><strong>UQAC</strong> — Département d’informatique et de mathématique — Stage en cybersécurité défensive (automne 2025).</p>
        </div>
        """),
        "rag": "Projet académique conduit par Lahat Fall sous la supervision du Pr. Jonathan Roy au département d’informatique de l’UQAC (stage cyberdéfensive automne 2025)."
    },
]
DOC_RAG_INDEX = SimpleRAG([{"title": sec["title"], "content": sec["rag"]} for sec in DOC_SECTIONS_DATA])

def load_yaml_config(path: Path) -> Dict[str, Any]:
    """Charge config.yaml en gérant les erreurs de manière explicite."""
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:  # noqa: BLE001
        st.warning(f"config.yaml invalide: {exc}")
        return {}


def first_alert_object(obj: object) -> Optional[Dict[str, object]]:
    """Retourne le premier enregistrement exploitable pour l’aperçu JSON."""
    if isinstance(obj, dict):
        if "_hits_sources" in obj and isinstance(obj["_hits_sources"], list):
            for candidate in obj["_hits_sources"]:
                if isinstance(candidate, dict):
                    return candidate
        if "_ndjson" in obj and isinstance(obj["_ndjson"], list):
            for candidate in obj["_ndjson"]:
                if isinstance(candidate, dict):
                    return candidate
        return obj
    if isinstance(obj, list):
        for candidate in obj:
            if isinstance(candidate, dict):
                return candidate
    return None


def summarize_alert_details(alert: Dict[str, Any]) -> List[str]:
    """Construit des phrases courtes décrivant les éléments clés d'une alerte Wazuh."""
    if not isinstance(alert, dict):
        return []
    lines: List[str] = []
    rule = alert.get("rule") or {}
    event = alert.get("event") or {}
    data = alert.get("data") or {}
    details = alert.get("fields", {}).get("rule", {}).get("mitre", {}).get("id")

    if rule:
        desc = rule.get("description") or ""
        rid = rule.get("id") or "?"
        level = rule.get("level")
        extras = []
        if level is not None:
            extras.append(f"niveau {level}")
        if rule.get("groups"):
            extras.append(", ".join(rule.get("groups")))
        extra_txt = f" ({'; '.join(extras)})" if extras else ""
        lines.append(f"Règle: {desc or '—'} [ID {rid}]{extra_txt}.")

    if event:
        severity = event.get("severity")
        action = event.get("action")
        dataset = event.get("dataset") or event.get("module")
        parts = []
        if severity is not None:
            parts.append(f"sévérité {severity}")
        if action:
            parts.append(f"action {action}")
        if dataset:
            parts.append(f"dataset {dataset}")
        if parts:
            lines.append("Contexte événement: " + ", ".join(parts) + ".")

    src = data.get("srcip") or data.get("src_ip")
    dst = data.get("dstip") or data.get("dst_ip")
    if src or dst:
        lines.append(f"Flux réseau: {src or '?'} → {dst or '?'}.")

    method = data.get("method")
    url = data.get("url")
    if url or method:
        lines.append(f"Requête HTTP: {method or '—'} {url or '—'}.")

    message = alert.get("message")
    if message:
        lines.append(f"Message: {message}")

    if details:
        try:
            joined = ", ".join(details)
        except TypeError:
            joined = str(details)
        lines.append(f"Champ fields.rule.mitre.id: {joined}.")

    return [line for line in lines if line]


def fetch_wazuh_alerts_from_api(cfg: Dict[str, Any], params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    client = WazuhClient(
        base_url=cfg.get("base_url", ""),
        username=cfg.get("username") or None,
        password=cfg.get("password") or None,
        token=cfg.get("token") or None,
        verify_tls=bool(cfg.get("verify_tls", True)),
        timeout=30,
    )
    return client.get_alerts(params=params)


def render_sidebar(meta: Dict[str, Any], techs: List[str], incidents_count: int, cfg_llm_enabled: bool) -> bool:
    """Affiche les informations de statut global et retourne l’état LLM pour la session."""
    with st.sidebar:
        st.markdown("### Statut en direct")
        st.metric("Techniques détectées", len(techs))
        st.metric("Incidents liés", incidents_count)
        last_ts = meta.get("timestamp") if meta else "—"
        st.metric("Dernière alerte", last_ts or "—")

        default_state = st.session_state.get("llm_active", cfg_llm_enabled)
        llm_toggle = st.checkbox(
            "Activer l’analyse LLM",
            value=default_state and cfg_llm_enabled,
            disabled=not cfg_llm_enabled,
            help="Désactive l’appel à Ollama pour cette session uniquement.",
        )
        st.session_state["llm_active"] = llm_toggle if cfg_llm_enabled else False

        if meta:
            with st.expander("Métadonnées de l’alerte", expanded=False):
                st.json(meta, expanded=False)

        st.caption("Les paramètres par défaut restent dictés par config.yaml.")
    return st.session_state["llm_active"]


def render_hero_section(
    meta: Dict[str, Any],
    techs: List[str],
    incidents_count: int,
    llm_active: bool,
) -> None:
    """Affiche la bannière principale avec résumé des entrées."""
    last_alert = meta.get("timestamp") or "—"
    agent_name = meta.get("agent.name") or meta.get("host.name") or "—"
    llm_label = "LLM actif" if llm_active else "LLM désactivé"
    llm_class = "" if llm_active else " is-off"
    logo_html = (
        f'<div class="cti-hero__logo-badge"><img src="data:image/jpeg;base64,{LOGO_B64}" alt="Logo CTI" /></div>'
        if LOGO_B64 else '<div class="cti-hero__logo-badge"><span>CTI<br/><small>UQAC 2025</small></span></div>'
    )
    stats_html = f"""<div class="cti-hero__stats">
<div class="cti-pill cti-pill--stat"><span class="cti-pill__icon">⚡</span>{len(techs)} techniques détectées</div>
<div class="cti-pill cti-pill--stat"><span class="cti-pill__icon">📁</span>{incidents_count} incidents corrélés</div>
<div class="cti-pill cti-pill--stat"><span class="cti-pill__icon">🕒</span>Dernière alerte : {last_alert}</div>
<div class="cti-pill cti-pill--stat"><span class="cti-pill__icon">🖥️</span>Agent : {agent_name}</div>
<div class="cti-pill cti-pill--stat{llm_class}"><span class="cti-pill__icon">🤖</span>{llm_label}</div>
</div>"""
    st.markdown(
        f"""
        <div class="cti-hero">
            {logo_html}
            <div>
                <div class="cti-hero__tag">Plate-forme MITRE ↔ VERIS ↔ VCDB</div>
                <h1>Cyber Threat Intelligent</h1>
                <p class="cti-hero__desc">
                    Corrélation ontologique des alertes Wazuh et recommandations SOC alimentées par LLM local.
                </p>
                {stats_html}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def humanize_label(value: str) -> str:
    return value.replace("_", " ").strip()


def format_tid_display(fragment: str) -> str:
    """Convertit un fragment MITRE en affichage standard (Txxxx[.xxx])."""
    frag = fragment.strip().upper()
    if "_" not in frag:
        return frag
    head, tail = frag.split("_", 1)
    return f"{head}.{tail.replace('_', '.')}"


def iri_label(graph: Graph, iri: str) -> str:
    """Récupère (avec cache) le rdfs:label d'une IRI."""
    if not iri:
        return ""
    if iri in LABEL_CACHE:
        return LABEL_CACHE[iri]
    label_value = ""
    try:
        node = next(graph.objects(URIRef(iri), RDFS.label), None)
        if node:
            label_value = str(node)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Impossible de récupérer le label pour %s: %s", iri, exc)
    LABEL_CACHE[iri] = label_value
    return label_value


def render_chip_group(title: str, items: List[str]) -> None:
    """Affiche une liste de valeurs sous forme de « chips » stylisées."""
    safe_title = escape(title)
    chips = (
        "".join(f'<span class="cti-chip">{escape(it)}</span>' for it in items)
        if items else '<span class="cti-chip is-empty">—</span>'
    )
    st.markdown(
        f'<div class="cti-chip-group"><div class="cti-chip-title">{safe_title}</div>{chips}</div>',
        unsafe_allow_html=True,
    )


MITRE_IRI_PREFIX = "http://example.org/mitre#"
MITRE_LABEL_CACHE_LOCAL: Dict[str, str] = {}


def tid_to_iri(tid: str) -> str:
    """Transforme un identifiant MITRE en IRI OWL."""
    if not tid:
        return ""
    normalized = tid.strip().upper().replace(".", "_")
    return f"{MITRE_IRI_PREFIX}{normalized}"


def resolve_tid_label(graph: Graph, tid: str) -> str:
    """Retourne le label MITRE pour un identifiant donné (via RDFS.label)."""
    iri = tid_to_iri(tid)
    if not iri:
        return ""
    return iri_label(graph, iri)


def get_tid_display_with_label(graph: Graph, fragment: str) -> str:
    """Assemble affichage formaté + label MITRE, avec mémoïsation locale."""
    tid_norm = fragment.strip().upper()
    if tid_norm not in MITRE_LABEL_CACHE_LOCAL:
        MITRE_LABEL_CACHE_LOCAL[tid_norm] = resolve_tid_label(graph, tid_norm) or ""
    label = MITRE_LABEL_CACHE_LOCAL[tid_norm] or humanize_label(fragment)
    return f"{format_tid_display(tid_norm)} — {label}"


def preview_list(items: List[str], limit: int = 6) -> str:
    """Crée une chaîne courte listant quelques éléments (utilisée pour l’auto-contexte)."""
    if not items:
        return "aucune"
    subset = items[:limit]
    suffix = "…" if len(items) > limit else ""
    return ", ".join(subset) + suffix


def get_incident_payload_cached(graph: Graph, incident_iri: str) -> Dict[str, List[str]]:
    """
    Charge actions/techniques/paires pour un incident en les mémoïsant
    afin d'éviter les requêtes SPARQL répétées à chaque rerun.
    """
    cache: Dict[str, Dict[str, List[str]]] = st.session_state.setdefault("_incident_details_cache", {})
    if incident_iri in cache:
        return cache[incident_iri]

    incident_actions = actions_for_incident(graph, incident_iri)
    explicit_techs = techniques_for_incident(graph, incident_iri)
    if not explicit_techs:
        explicit_techs = deduce_incident_techs(graph, incident_iri)
    action_pairs = actions_to_tech_pairs(graph, incident_actions)

    payload = {
        "actions": incident_actions,
        "techniques": explicit_techs,
        "pairs": action_pairs,
    }
    cache[incident_iri] = payload
    return payload


# ===============================
#   Lecture config.yaml
# ===============================
cfg_path = Path("config.yaml")
cfg: dict = load_yaml_config(cfg_path)

OWL_FILE   = cfg.get("owl_file",   "data/sample-unified-materialized.owl")
ALERT_FILE = cfg.get("alert_file", "data/alert.json")
LLM_ENABLE = bool(cfg.get("llm", {}).get("enable", True))
LLM_MODEL  = cfg.get("llm", {}).get("model", "llama3.2:1b")  # tu n’as que ce modèle installé pour l’instant
WAZUH_API_CFG = cfg.get("wazuh_api", {}) or {}


# ===============================
#   Caches (Graph + lecture alerte)
# ===============================
@st.cache_resource(show_spinner=False)
def load_graph(path: str) -> Graph:
    """Charge un graphe RDF (TTL → fallback XML)."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(path)
    g = Graph()
    data = file_path.read_bytes()
    txt  = data.decode("utf-8", errors="ignore")
    try:
        g.parse(data=txt, format="turtle")
    except Exception:
        g.parse(data=txt, format="xml")
    return g

@st.cache_data(show_spinner=False)
def load_alert_text(p: str) -> str:
    """Charge un JSON/NDJSON d’alerte par défaut si présent."""
    path = Path(p)
    if not path.exists():
        return "{}"
    return path.read_text(encoding="utf-8", errors="ignore")


# ===============================
#   Session state initial
# ===============================
default_wazuh_cfg = {
    "base_url": WAZUH_API_CFG.get("base_url", ""),
    "username": WAZUH_API_CFG.get("username", ""),
    "password": WAZUH_API_CFG.get("password", ""),
    "token": WAZUH_API_CFG.get("token", ""),
    "verify_tls": bool(WAZUH_API_CFG.get("verify_tls", True)),
}

for k, v in [
    ("selected_incident", None),
    ("obj_alert", None),
    ("tech_ids", []),
    ("llm_response", ""),
    ("llm_active", LLM_ENABLE),
    ("incident_filter", ""),
    ("min_action_filter", 0),
    ("analyst_note", ""),
    ("wazuh_api", default_wazuh_cfg.copy()),
    ("incidents_cache_key", tuple()),
    ("incidents", []),
    ("_incident_details_cache", {}),
    ("chain_show_all", False),
]:
    if k not in st.session_state:
        st.session_state[k] = v


# ===============================
#   Données sources (OWL + Alerte)
# ===============================
try:
    g = load_graph(OWL_FILE)
except FileNotFoundError:
    st.error(f"Fichier OWL introuvable : {OWL_FILE}")
    st.stop()
except Exception as exc:  # noqa: BLE001
    st.error(f"Impossible de charger l’ontologie : {exc}")
    st.stop()

# Lecture alerte par défaut
raw_alert = load_alert_text(ALERT_FILE)
obj_alert_default = load_wazuh_alerts_any(raw_alert)

# État courant (permet MAJ après import)
obj_alert = st.session_state.get("obj_alert") or obj_alert_default
tech_ids  = st.session_state.get("tech_ids") or extract_tech_ids_universal(obj_alert)
st.session_state["obj_alert"] = obj_alert
st.session_state["tech_ids"]  = tech_ids
alert_meta = extract_alert_metadata(obj_alert)


# ===============================
#   Résumé + Navigation
# ===============================
current_key = tuple(sorted(tech_ids or []))
cached_key = st.session_state.get("incidents_cache_key")
if cached_key != current_key:
    computed_incidents = get_incidents_by_tech(g, tech_ids) if tech_ids else []
    st.session_state["incidents"] = computed_incidents
    st.session_state["incidents_cache_key"] = current_key
incidents = st.session_state.get("incidents", [])
LLM_RUNTIME_ENABLED = render_sidebar(alert_meta or {}, tech_ids, len(incidents), LLM_ENABLE)
render_hero_section(alert_meta or {}, tech_ids, len(incidents), LLM_RUNTIME_ENABLED)

tabs = st.tabs([
    "🏠 Accueil",
    "📊 Tableau de bord",
    "🗂️ Incidents",
    "🔍 Détail incident",
    "📥 Flux d’alertes",
    "⚙️ Paramètres",
    "📘 Documentation"
])


# ===============================
#   Accueil
# ===============================
with tabs[0]:
    st.markdown("""
<div class="cti-grid">
  <div class="cti-card">
    <h4>Objectif</h4>
    <p>Corréler des <b>alertes Wazuh</b> avec des <b>techniques MITRE</b>, <b>actions VERIS</b> et <b>incidents VCDB</b>, puis produire une analyse SOC opérationnelle.</p>
  </div>
  <div class="cti-card">
    <h4>Pipeline</h4>
    <ol>
      <li>Extraction T-IDs (JSON/NDJSON/API Wazuh)</li>
      <li>Jointure ontologique (OWL)</li>
      <li>Classement des incidents</li>
      <li>Analyse LLM locale (Ollama)</li>
      <li>Génération d’un rapport</li>
    </ol>
  </div>
  <div class="cti-card">
    <h4>Statut</h4>
    <ul>
      <li>OWL: chargé</li>
      <li>LLM: {llm}</li>
      <li>Entrées: JSON/NDJSON (API possible)</li>
    </ul>
  </div>
  <div class="cti-card">
    <h4>Crédits</h4>
    <p><b>Lahat Fall</b> — UQAC<br/>Projet-stage en cybersécurité défensive.</p>
  </div>
</div>
""".replace("{llm}", "activé" if LLM_RUNTIME_ENABLED else "désactivé"), unsafe_allow_html=True)


# ===============================
#   Tableau de bord
# ===============================
with tabs[1]:
    st.subheader("Tableau de bord")
    meta = alert_meta or {}
    alert_snapshot = first_alert_object(obj_alert) or {}
    event_info = alert_snapshot.get("event") or {}
    rule_info = alert_snapshot.get("rule") or {}
    data_info = alert_snapshot.get("data") or {}
    mitre_field_ids = (alert_snapshot.get("fields") or {}).get("rule", {}).get("mitre", {}).get("id") or []

    def fmt_text(value: object) -> str:
        if value is None:
            return "—"
        if isinstance(value, str):
            txt = value.strip()
            return escape(txt) if txt else "—"
        return escape(str(value))

    def format_tid_values(values: Optional[List[str]]) -> List[str]:
        formatted: List[str] = []
        for val in values or []:
            if not val:
                continue
            token = str(val).strip()
            if not token:
                continue
            normalized = token.replace(".", "_")
            formatted.append(format_tid_display(normalized))
        return formatted

    def chipline(values: List[str]) -> str:
        rendered = []
        for val in values:
            if not val:
                continue
            token = str(val).strip()
            if not token:
                continue
            rendered.append(escape(token))
        if not rendered:
            return '<span class="dash-chip is-empty">—</span>'
        return "".join(f'<span class="dash-chip">{val}</span>' for val in rendered)

    def metric_value(value: object) -> str:
        if value in (None, ""):
            return "—"
        return str(value)

    severity_value = event_info.get("severity")
    rule_level = rule_info.get("level")
    kpis = [
        ("⚡", "Techniques extraites", metric_value(len(set(tech_ids or [])))),
        ("📁", "Incidents corrélés", metric_value(len(incidents))),
        ("🔥", "Sévérité (event)", metric_value(severity_value)),
        ("🛡️", "Niveau de règle", metric_value(rule_level)),
    ]
    kpi_html = "<div class='dashboard-kpis'>" + "".join(
        f"<div class='dash-kpi'><span class='dash-kpi__icon'>{escape(icon)}</span>"
        f"<div><small>{escape(label)}</small><strong>{escape(value)}</strong></div></div>"
        for icon, label, value in kpis
    ) + "</div>"
    st.markdown(kpi_html, unsafe_allow_html=True)

    timestamp_val = meta.get("timestamp") or alert_snapshot.get("@timestamp") or event_info.get("created") or event_info.get("ingested")
    agent_name = meta.get("agent.name") or (alert_snapshot.get("agent") or {}).get("name")
    manager_name = (alert_snapshot.get("manager") or {}).get("name")
    dataset = event_info.get("dataset")
    module = event_info.get("module")
    action_taken = event_info.get("action")
    log_location = alert_snapshot.get("location") or alert_snapshot.get("location_id")
    decoder_name = (alert_snapshot.get("decoder") or {}).get("name")
    tags = alert_snapshot.get("tags") or []
    rule_desc = rule_info.get("description") or meta.get("rule.description") or "Alerte Wazuh"
    rule_id = rule_info.get("id") or meta.get("rule.id") or "—"
    message_text = alert_snapshot.get("message") or meta.get("rule.description") or ""

    detected_tid_display = format_tid_values(sorted(set(tech_ids or [])))
    mitre_rule_ids = format_tid_values(rule_info.get("mitre", {}).get("id"))
    mitre_fields_display = format_tid_values(mitre_field_ids)
    mitre_desc = rule_info.get("mitre", {}).get("technique") or []
    mitre_tactics = rule_info.get("mitre", {}).get("tactic") or []
    rule_groups = rule_info.get("groups") or []

    src_ip = data_info.get("srcip")
    dst_ip = data_info.get("dstip")
    flow_text = f"{src_ip or '—'} → {dst_ip or '—'}"
    method = data_info.get("method")
    url = data_info.get("url")
    user_agent = data_info.get("http_user_agent")
    extra = data_info.get("extra") or {}
    matched_payload = extra.get("matched_techniques")
    decoded_payload = extra.get("decoded_payload")

    http_rows = [
        ("Méthode", fmt_text(method)),
        ("URL", fmt_text(url)),
        ("User-Agent", fmt_text(user_agent)),
    ]
    if matched_payload:
        http_rows.append(("Techniques détectées (payload)", fmt_text(matched_payload)))
    http_rows_html = "".join(
        f"<tr><th>{escape(label)}</th><td>{value}</td></tr>" for label, value in http_rows
    )

    body_pre = escape(data_info.get("body")) if data_info.get("body") else "—"
    decoded_pre = escape(decoded_payload) if decoded_payload else "—"
    message_html = escape(message_text.strip()) if message_text else "Aucune description fournie."

    dashboard_html = f"""
    <div class="dashboard-grid">
      <section class="dash-card dash-card--primary">
        <div class="dash-card__header">
          <span class="dash-chip">Règle {fmt_text(rule_id)}</span>
          <h3>{fmt_text(rule_desc)}</h3>
          <p class="dash-card__subtitle">{message_html}</p>
        </div>
        <div class="dash-meta-grid">
          <div class="dash-meta">
            <span>Horodatage</span>
            <strong>{fmt_text(timestamp_val)}</strong>
            <small>Ingesté : {fmt_text(event_info.get('ingested'))}</small>
          </div>
          <div class="dash-meta">
            <span>Agent & manager</span>
            <strong>{fmt_text(agent_name)}</strong>
            <small>Manager : {fmt_text(manager_name)}</small>
          </div>
          <div class="dash-meta">
            <span>Module / dataset</span>
            <strong>{fmt_text(module)}</strong>
            <small>{fmt_text(dataset)}</small>
          </div>
          <div class="dash-meta">
            <span>Action & sévérité</span>
            <strong>{fmt_text(action_taken)}</strong>
            <small>Sévérité : {fmt_text(severity_value)}</small>
          </div>
          <div class="dash-meta">
            <span>Source du log</span>
            <strong>{fmt_text(log_location)}</strong>
            <small>Décodeur : {fmt_text(decoder_name)}</small>
          </div>
        </div>
      </section>
      <section class="dash-card">
        <h4>MITRE & corrélation</h4>
        <div class="dash-block">
          <small>Techniques de l’alerte</small>
          <div class="dash-chipline">{chipline(detected_tid_display)}</div>
        </div>
        <div class="dash-block">
          <small>MITRE (rule.id)</small>
          <div class="dash-chipline">{chipline(mitre_rule_ids)}</div>
        </div>
        <div class="dash-block">
          <small>MITRE (fields.rule)</small>
          <div class="dash-chipline">{chipline(mitre_fields_display)}</div>
        </div>
        <div class="dash-block">
          <small>Tactiques & groupes</small>
          <div class="dash-chipline">{chipline(mitre_tactics + rule_groups)}</div>
        </div>
        <div class="dash-block">
          <small>Descriptions</small>
          <div class="dash-chipline">{chipline(mitre_desc)}</div>
        </div>
      </section>
      <section class="dash-card">
        <h4>Couche réseau & tags</h4>
        <ul class="dash-list">
          <li><span>Flux</span><strong>{fmt_text(flow_text)}</strong></li>
          <li><span>Méthode</span><strong>{fmt_text(method)}</strong></li>
          <li><span>URL</span><strong>{fmt_text(url)}</strong></li>
          <li><span>Tags</span><strong>{fmt_text(', '.join(tags) if tags else '—')}</strong></li>
        </ul>
        <div class="dash-chipline">{chipline(tags)}</div>
      </section>
      <section class="dash-card dash-card--wide">
        <h4>Requête HTTP & payload</h4>
        <table class="dash-http-table">
          {http_rows_html}
        </table>
        <div class="dash-pre-block">
          <small>Corps encodé</small>
          <pre class="dash-pre">{body_pre}</pre>
          <small>Payload décodé</small>
          <pre class="dash-pre">{decoded_pre}</pre>
        </div>
      </section>
    </div>
    """
    st.markdown(dashboard_html, unsafe_allow_html=True)

    with st.expander("Structure JSON complète de l’alerte", expanded=False):
        st.json(alert_snapshot or {"info": "Alerte indisponible"}, expanded=False)


# ===============================
#   Incidents (liste + sélection)
# ===============================

with tabs[2]:
    st.subheader("Classement des incidents  suivant le nombre d'actions Correspondants aux techniques Mitre   ")

    if not tech_ids:
        st.info("Aucune technique MITRE détectée dans l’alerte actuelle. Importe un JSON/NDJSON dans l’onglet « Flux d’alertes ».")
    elif not incidents:
        st.info("Aucun incident trouvé pour ces techniques.")
    else:
        rows = []
        for inc in incidents:
            inc_actions = actions_for_incident(g, inc)
            inc_techs   = techniques_for_incident(g, inc) or deduce_incident_techs(g, inc)
            rows.append({
                "IRI": inc,
                "Incident": lastfrag(inc),
                "Nb actions": len(set(inc_actions)),
                "Actions": ", ".join(sorted({ lastfrag(a) for a in inc_actions })) or "—",
                "Techniques": ", ".join(sorted({ lastfrag(t) for t in inc_techs })) or "—",
            })

        df = pd.DataFrame(rows).sort_values(["Nb actions","Incident"], ascending=[False, True])

        cfilter, cslider = st.columns([0.7, 0.3])
        with cfilter:
            st.text_input(
                "Filtrer par nom d’incident, action ou technique",
                key="incident_filter",
                placeholder="Ex.: ransomware, phishing…",
            )
            filter_query = st.session_state.get("incident_filter", "").strip()
        with cslider:
            slider_max = int(df["Nb actions"].max()) if not df.empty else 0
            min_val = min(st.session_state.get("min_action_filter", 0), slider_max)
            min_actions = st.slider(
                "Nb d’actions minimum",
                min_value=0,
                max_value=slider_max if slider_max > 0 else 0,
                value=min_val,
                help="Affiche uniquement les incidents ayant au moins ce nombre d’actions mappées.",
            )
            st.session_state["min_action_filter"] = min_actions

        filtered_df = df
        if filter_query:
            mask = (
                df["Incident"].str.contains(filter_query, case=False, na=False)
                | df["Actions"].str.contains(filter_query, case=False, na=False)
                | df["Techniques"].str.contains(filter_query, case=False, na=False)
            )
            filtered_df = df[mask]
        if min_actions:
            filtered_df = filtered_df[filtered_df["Nb actions"] >= min_actions]

        if filtered_df.empty:
            st.info("Aucun incident ne correspond aux filtres appliqués.")
            incident_opts = []
        else:
            st.dataframe(
                filtered_df[["Incident", "Nb actions", "Actions", "Techniques"]],
                use_container_width=True,
                hide_index=True,
            )
            options = filtered_df[["Incident","IRI","Nb actions"]].to_dict(orient="records")
            incident_opts = [rec["IRI"] for rec in options]

        options = filtered_df[["Incident","IRI","Nb actions"]].to_dict(orient="records") if not filtered_df.empty else []
        labels = {rec["IRI"]: f"{rec['Incident']} — {rec['Nb actions']} action(s)" for rec in options}

        sel = st.selectbox(
            "Sélectionner un incident",
            options=incident_opts,
            format_func=lambda iri: labels.get(iri, iri),
            index=0 if incident_opts else None,
            placeholder="Choisir…"
        )
        if sel:
            st.session_state["selected_incident"] = sel

        # Raccourci reset
        if st.button("↺ Réinitialiser la sélection"):
            st.session_state["selected_incident"] = None
            st.session_state["llm_response"] = ""
            st.success("Contexte réinitialisé.")


# ===============================
#   Détail incident + LLM + Rapport
# ===============================
with tabs[3]:
    inc = st.session_state.get("selected_incident")
    if not inc:
        st.info("Sélectionne un incident dans l’onglet « Incidents ».")
    else:
        st.subheader(f"Détail — {lastfrag(inc)}")

        # Données incident (cachées après premier calcul)
        inc_payload = get_incident_payload_cached(g, inc)
        inc_actions = inc_payload.get("actions", [])
        inc_techs   = inc_payload.get("techniques", []) or []
        pairs       = inc_payload.get("pairs", [])

        # Filtrage visuel par techniques de l’alerte (activable/désactivable)
        def _iri_mitre_from_tid(tid: str) -> str:
            return tid_to_iri(tid)
        tech_nodes = { _iri_mitre_from_tid(t) for t in (tech_ids or []) }
        show_all_chain = st.checkbox(
            "Afficher toutes les techniques de l’incident (pas uniquement celles détectées dans l’alerte)",
            value=st.session_state.get("chain_show_all", False),
            help="Par défaut, seule la chaîne correspondant aux techniques extraites de l’alerte est représentée.",
        )
        st.session_state["chain_show_all"] = show_all_chain
        visible_pairs = pairs
        if (not show_all_chain) and tech_nodes:
            visible_pairs = [(a, t) for (a, t) in pairs if t in tech_nodes]
        visible_pair_set = visible_pairs

        c1, c2 = st.columns([0.55, 0.45])

        with c1:
            actions_list = sorted({ humanize_label(lastfrag(x)) for x in inc_actions })
            tech_entries = []
            visible_fragments = { lastfrag(t) for _, t in visible_pair_set }
            if not visible_fragments:
                visible_fragments = { lastfrag(str(x)) for x in inc_techs }
            source_iter = [
                str(x) for x in inc_techs
                if lastfrag(str(x)) in visible_fragments
            ] or [str(x) for x in inc_techs]
            for iri in sorted(set(source_iter)):
                frag = lastfrag(iri)
                tech_entries.append(get_tid_display_with_label(g, frag))
            uniq_actions = len(set(inc_actions))
            uniq_techs = len(set(inc_techs))

            details_html = f"""
            <div class="details-panel">
                <div class="details-meta">
                    <div class="panel-title">Synthèse</div>
                    <code>{escape(inc)}</code>
                </div>
                <div class="details-grid">
                    <div class="details-card">
                        <span>Nb actions</span>
                        <strong>{uniq_actions}</strong>
                    </div>
                    <div class="details-card">
                        <span>Nb techniques</span>
                        <strong>{uniq_techs}</strong>
                    </div>
                    <div class="details-card">
                        <span>Techniques détectées (alerte)</span>
                        <strong>{len(set(tech_ids or []))}</strong>
                    </div>
                </div>
            </div>
            """
            st.markdown(details_html, unsafe_allow_html=True)

            render_chip_group("Actions VERIS corrélées", actions_list)

            max_visible = 12
            render_chip_group(
                f"Techniques MITRE impliquées (top {min(max_visible, len(tech_entries))})",
                tech_entries[:max_visible]
            )
            if len(tech_entries) > max_visible:
                with st.expander(f"Voir les {len(tech_entries) - max_visible} autres techniques", expanded=False):
                    render_chip_group("Suite des techniques MITRE", tech_entries[max_visible:])

            scope_label = (
                "complète (toutes les techniques incident)"
                if show_all_chain or not tech_nodes
                else "filtrée sur les techniques détectées dans l’alerte"
            )
            st.markdown(f"#### Cartographie MITRE ↔ VERIS — vue {scope_label}")
            if visible_pair_set:
                tech_to_actions: Dict[str, set[str]] = {}
                for action_iri, tech_iri in visible_pair_set:
                    frag = lastfrag(tech_iri)
                    tech_to_actions.setdefault(frag, set()).add(humanize_label(lastfrag(action_iri)))
                summary_rows = []
                for frag in sorted(tech_to_actions):
                    tid_display = format_tid_display(frag)
                    label = resolve_tid_label(g, frag) or humanize_label(frag)
                    actions_text = ", ".join(sorted(tech_to_actions[frag])) or "—"
                    summary_rows.append({
                        "Technique": tid_display,
                        "Nom MITRE": label,
                        "Actions VERIS associées": actions_text,
                    })
                df_summary = pd.DataFrame(summary_rows)
                st.dataframe(df_summary, use_container_width=True, hide_index=True)
            else:
                st.caption("Aucune association Technique ↔ Action à afficher dans la chaîne courante.")

            # Rapport HTML (inclura l’analyse LLM si déjà générée)
            llm_response = st.session_state.get("llm_response", "")
            # Appel compatible avec ancienne / nouvelle signature du module report
            report_html: str
            try:
                report_html = build_html_report(
                    platform="Cyber Threat Intelligent",
                    author="Lahat Fall (UQAC)",
                    alert_meta=alert_meta,
                    tech_ids=tech_ids,
                    incident_iri=inc,
                    actions=[lastfrag(x) for x in inc_actions],
                    techniques=[lastfrag(x) for x in inc_techs],
                    llm_text=llm_response,
                    llm_model=LLM_MODEL if LLM_RUNTIME_ENABLED else None
                )
            except TypeError:
                # Rétrocompatibilité si build_html_report n’accepte pas llm_text/llm_model
                report_html = build_html_report(
                    platform="Cyber Threat Intelligent",
                    author="Lahat Fall (UQAC)",
                    alert_meta=alert_meta,
                    tech_ids=tech_ids,
                    incident_iri=inc,
                    actions=[lastfrag(x) for x in inc_actions],
                    techniques=[lastfrag(x) for x in inc_techs]
                )

            st.download_button(
                "📥 Télécharger le rapport (HTML)",
                data=report_html.encode("utf-8"),
                file_name="rapport_cti.html",
                mime="text/html"
            )

        with c2:
            st.markdown(
                '<div class="panel-title">Chaîne sémantique · Alerte → Techniques → Actions → Incident</div>',
                unsafe_allow_html=True,
            )
            if visible_pair_set:
                fig = draw_chain_enriched(tech_ids, visible_pair_set, lastfrag(inc))
                st.pyplot(fig, clear_figure=True)
                st.caption(
                    "Vue statique optimisée (mode interactif retiré pour accélérer l'application)."
                )
            else:
                st.caption("Aucun lien Technique→Action matérialisé pour cet incident (chaîne réduite).")

        st.markdown("---")
        st.markdown("### Analyse & recommandations (LLM local)")

        if LLM_RUNTIME_ENABLED:
            auto_context_lines = [
                f"Alerte Wazuh datée du {alert_meta.get('timestamp', 'inconnue') or 'inconnue'} sur l’agent {alert_meta.get('agent.name', 'non spécifié') or 'non spécifié'}.",
                f"Incident corrélé : {lastfrag(inc)}.",
                f"Techniques extraites : {', '.join(tech_ids) if tech_ids else 'aucune TID détectée.'}",
                f"Actions VERIS associées : {preview_list(actions_list, limit=6)}.",
            ]
            alert_summary = summarize_alert_details(first_alert_object(obj_alert))
            auto_context_lines.extend(alert_summary)
            auto_context = "\n".join(auto_context_lines)
            auto_context_html = "<br/>".join(escape(line) for line in auto_context_lines)
            st.markdown("**Contexte transmis automatiquement au LLM**")
            st.markdown(f"<div class='auto-context'>{auto_context_html}</div>", unsafe_allow_html=True)

            with st.expander("Ajouter un complément analyste (optionnel)", expanded=False):
                st.text_area(
                    "Complément analyste",
                    key="analyst_note",
                    placeholder="Hypothèses spécifiques, impacts métier, contraintes…",
                    label_visibility="collapsed",
                )

            extra_note = st.session_state.get("analyst_note", "").strip()
            analyst_context = auto_context
            if extra_note:
                analyst_context = f"{auto_context}\n\nConsigne analyste : {extra_note}"

            rag_query_parts = [lastfrag(inc), " ".join(tech_ids or []), " ".join(actions_list), extra_note]
            rag_query = " ".join(part for part in rag_query_parts if part).strip() or lastfrag(inc)
            rag_chunks = DOC_RAG_INDEX.search(rag_query, top_k=3)
            rag_texts = [chunk["content"] for chunk in rag_chunks]
            if rag_chunks:
                st.markdown("**Documentation récupérée (RAG)**")
                for chunk in rag_chunks:
                    st.markdown(f"- **{chunk['title']}** · {chunk['snippet']}")
            else:
                rag_texts = []

            if st.button("Générer l’analyse", type="primary"):
                prompt = build_prompt(
                    incident_iri=inc,
                    tech_alert=tech_ids,
                    inc_techs=[lastfrag(x) for x in inc_techs],
                    inc_actions=[lastfrag(x) for x in inc_actions],
                    analyst_context=analyst_context,
                    knowledge_chunks=rag_texts,
                )
                try:
                    out = call_ollama(prompt, model=LLM_MODEL, timeout=90)
                    st.session_state["llm_response"] = out or ""
                    st.markdown(st.session_state["llm_response"] or "(réponse vide)")
                except Exception as e:
                    st.error(f"LLM local indisponible: {e}")
        else:
            st.info("LLM désactivé pour cette session (active-le via la barre latérale ou config.yaml).")


# ===============================
#   Flux d’alertes (import)
# ===============================
with tabs[4]:
    st.subheader("Flux d’alertes (fichier local)")
    up = st.file_uploader("Importer un JSON/NDJSON (Wazuh)", type=["json","ndjson"], accept_multiple_files=False)
    if up is not None:
        raw = up.read().decode("utf-8", errors="ignore")
        obj2 = load_wazuh_alerts_any(raw)

        # MAJ état global
        st.session_state["obj_alert"] = obj2
        obj_alert = obj2

        tech_ids2 = extract_tech_ids_universal(obj2)
        st.session_state["tech_ids"] = tech_ids2
        tech_ids = tech_ids2

        # Recalcule incidents et sélection
        incidents2 = get_incidents_by_tech(g, tech_ids2) if tech_ids2 else []
        st.session_state["selected_incident"] = incidents2[0] if incidents2 else None
        st.session_state["incidents"] = incidents2
        st.session_state["incidents_cache_key"] = tuple(sorted(tech_ids2))
        incidents = incidents2
        alert_meta = extract_alert_metadata(obj_alert)

        st.success(f"Alerte chargée. T-IDs détectés : {' '.join(tech_ids2) if tech_ids2 else '(aucun)'}")

    else:
        st.caption("Astuce : place un fichier par défaut dans data/alert.json.")

    with st.expander("Connexion API Wazuh", expanded=False):
        wazuh_cfg = st.session_state.get("wazuh_api", default_wazuh_cfg.copy())
        with st.form("wazuh_api_form"):
            base_url = st.text_input("URL API", value=wazuh_cfg.get("base_url", ""), placeholder="https://wazuh.local:55000")
            col_creds = st.columns(2)
            with col_creds[0]:
                username = st.text_input("Utilisateur", value=wazuh_cfg.get("username", ""))
            with col_creds[1]:
                password = st.text_input("Mot de passe", value=wazuh_cfg.get("password", ""), type="password")
            token = st.text_input("Token (optionnel)", value=wazuh_cfg.get("token", ""), help="Ignorer utilisateur/mot de passe si un token est saisi.")
            verify_tls = st.checkbox("Vérifier le certificat TLS", value=bool(wazuh_cfg.get("verify_tls", True)))
            default_params = "{\"limit\": 50, \"sort\": \"-timestamp\"}"
            params_raw = st.text_area("Paramètres (JSON)", value=wazuh_cfg.get("last_params", default_params), height=100)
            submitted = st.form_submit_button("Interroger Wazuh", type="primary")

        if submitted:
            if not base_url.strip():
                st.error("Merci de renseigner l’URL de l’API Wazuh.")
            else:
                try:
                    params = json.loads(params_raw) if params_raw.strip() else None
                except json.JSONDecodeError as exc:
                    st.error(f"Paramètres JSON invalides: {exc}")
                    params = None
                if params is not None:
                    cfg_call = {
                        "base_url": base_url.strip(),
                        "username": username.strip(),
                        "password": password,
                        "token": token.strip(),
                        "verify_tls": verify_tls,
                    }
                    try:
                        resp = fetch_wazuh_alerts_from_api(cfg_call, params)
                        parsed = load_wazuh_alerts_any(resp)
                    except Exception as exc:  # noqa: BLE001
                        st.error(f"Échec de l’appel API Wazuh: {exc}")
                    else:
                        st.session_state["wazuh_api"] = {**cfg_call, "last_params": params_raw}
                        st.session_state["obj_alert"] = parsed
                        obj_alert = parsed
                        tech_ids_api = extract_tech_ids_universal(parsed)
                        st.session_state["tech_ids"] = tech_ids_api
                        tech_ids = tech_ids_api
                        incidents_api = get_incidents_by_tech(g, tech_ids_api) if tech_ids_api else []
                        st.session_state["selected_incident"] = incidents_api[0] if incidents_api else None
                        st.session_state["incidents"] = incidents_api
                        st.session_state["incidents_cache_key"] = tuple(sorted(tech_ids_api))
                        incidents = incidents_api
                        alert_meta = extract_alert_metadata(obj_alert)
                        total_items = resp.get("data", {}).get("totalItems") if isinstance(resp, dict) else None
                        msg = f"{total_items} alertes" if total_items is not None else "Alerte récupérée"
                        st.success(f"{msg}. T-IDs détectés : {' '.join(tech_ids_api) if tech_ids_api else '(aucun)'}")

    st.markdown("**Aperçu des entrées chargées**")
    show_meta_preview = st.checkbox(
        "Calculer l’aperçu (désactive si des milliers d’événements)",
        value=False,
        key="meta_preview_toggle",
        help="L’extraction des métadonnées peut être coûteuse sur de gros lots NDJSON. Active uniquement lorsque nécessaire.",
    )
    if show_meta_preview:
        metas_current = extract_all_alerts_metadata(obj_alert)
        if metas_current:
            df_meta = pd.DataFrame(metas_current)
            if len(df_meta) > 200:
                st.caption("Affichage limité aux 200 premières entrées.")
                df_meta = df_meta.head(200)
            st.dataframe(df_meta, use_container_width=True, hide_index=True)
        else:
            st.caption("Aucune métadonnée exploitable pour l’alerte en cours.")
    else:
        st.caption("Active la case ci-dessus pour charger les métadonnées (non calculées par défaut).")

    preview = first_alert_object(obj_alert)
    if preview:
        with st.expander("Aperçu JSON brut (premier enregistrement)", expanded=False):
            st.json(preview, expanded=False)
    else:
        st.caption("Aucun enregistrement JSON exploitable à afficher.")


# ===============================
#   Paramètres
# ===============================
with tabs[5]:
    st.subheader("Paramètres")
    st.markdown(f"- Fichier OWL actuel : `{OWL_FILE}`")
    st.markdown(f"- Fichier d’alerte par défaut : `{ALERT_FILE}`")
    st.markdown(f"- LLM local : {'activé' if LLM_ENABLE else 'désactivé'}")
    st.markdown(f"- LLM (session actuelle) : {'activé' if LLM_RUNTIME_ENABLED else 'désactivé'}")
    st.markdown(f"- Modèle LLM : `{LLM_MODEL}`")


# ===============================
#   Documentation (complète)
# ===============================
with tabs[6]:
    st.subheader("Documentation — Plateforme CTI sémantique")
    st.markdown('<div class="doc-container">', unsafe_allow_html=True)
    for idx, section in enumerate(DOC_SECTIONS_DATA):
        st.markdown(section["html"], unsafe_allow_html=True)
        if idx != len(DOC_SECTIONS_DATA) - 1:
            st.markdown('<div class="doc-divider"></div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

footer_signature()  # Pied de page signé
