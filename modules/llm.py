# -*- coding: utf-8 -*-
"""
Cyber Threat Intelligent — Module llm
Objectif: Wrapper Ollama + prompt contextuel

Développeur : Lahat Fall et MARC (UQAC) — Projet-stage en cybersécurité défensive.
© 2025, Tous droits réservés.
"""
from __future__ import annotations

import logging
import textwrap

import requests

logger = logging.getLogger(__name__)


def call_ollama(prompt: str, model: str = "llama3.2:1b", timeout: int = 90) -> str:
    """Appelle l'API Ollama locale en veillant à remonter toute erreur HTTP."""
    url = "http://localhost:11434/api/generate"
    payload = {"model": model, "prompt": prompt, "stream": False}
    r = requests.post(url, json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json().get("response", "")


def build_prompt(
    incident_iri: str,
    tech_alert: list[str],
    inc_techs: list[str],
    inc_actions: list[str],
    analyst_context: str = "",
    knowledge_chunks: list[str] | None = None,
) -> str:
    """Assemble un prompt structuré et contextualisé pour l'analyste virtuel."""
    sys = textwrap.dedent("""
    Tu es un analyste SOC senior spécialisé en corrélation MITRE ATT&CK ↔ VERIS ↔ incidents.

    [Rôle]
    Ton rôle est STRICTEMENT limité à :
    1) Interpréter la chaîne Techniques MITRE → Actions VERIS → Incident.
    2) Expliquer le lien entre chaque technique MITRE et les actions VERIS associées.
    3) Recommandation, remédiation ou défense.
    [Interdictions]
    - Ne calcule aucun score, probabilité, priorité ou niveau de risque.
    - N’invente pas de techniques, d’actions ou d’incidents qui ne figurent pas
      dans les données fournies.
    - Si une information manque, écris « Inconnu » ou « Non précisé ».

    [Format de sortie OBLIGATOIRE]

    [1. Interprétation de la chaîne]
    Explique en 3–6 phrases comment les techniques MITRE observées dans l’alerte
    se relient aux techniques MITRE et aux actions VERIS associées à l’incident, 
    et pourquoi cet incident est cohérent avec cette chaîne.

    [2. Lien MITRE ↔ VERIS]
    Pour chaque technique MITRE pertinente, liste sous forme de puces :
    - Technique MITRE : <ID et nom si possible> 
      → Actions VERIS liées : <liste>
      → Explication courte (1–2 phrases) du lien logique.
      

    Ne produis rien en dehors de ces deux sections.
    """).strip()

    user = textwrap.dedent(f"""
    [Incident]
    IRI: {incident_iri}

    [Techniques MITRE de l’alerte]
    {", ".join(sorted(set(tech_alert))) or "(aucune)"}

    [Techniques MITRE associées à l’incident]
    {", ".join(sorted(set(inc_techs))) or "(aucune)"}

    [Actions VERIS associées à l’incident]
    {", ".join(sorted(set(inc_actions))) or "(aucune)"}
    """).strip()

    if analyst_context.strip():
        user += "\n\n[Contexte analyste]\n" + analyst_context.strip()

    if knowledge_chunks:
        snippets = [chunk.strip() for chunk in knowledge_chunks if chunk and chunk.strip()]
        if snippets:
            user += "\n\n[Connaissances externes]\n" + "\n\n".join(snippets)

    return sys + "\n\n" + user
