# -*- coding: utf-8 -*-
"""
Cyber Threat Intelligent — Module ontology
Objectif: Requêtes RDF/OWL pour incidents, actions VERIS & techniques MITRE

Développeur : Lahat Fall (UQAC) — Projet-stage en cybersécurité défensive.
© 2025, Tous droits réservés.

Points clés:
- Normalisation robuste des T-IDs (ex: "t1059.001" -> "T1059_001")
- get_incidents_by_tech: SPARQL tolérant + fallback en scan RDF si besoin
- Fonctions utilitaires inchangées pour le reste de l'app
"""

from __future__ import annotations

import logging
from typing import List, Tuple

from rdflib import RDF, Graph, Namespace, URIRef

logger = logging.getLogger(__name__)

# Namespaces (doivent correspondre à l’OWL)
BRIDGE = Namespace("http://example.org/bridge#")
VERIS  = Namespace("http://example.org/veris#")

# ---------------------------------------------------------------------
# Utils
# ---------------------------------------------------------------------
def lastfrag(iri: str) -> str:
    """Retourne le fragment final d'une IRI (après # ou dernier /)."""
    if "#" in iri:
        return iri.split("#")[-1]
    if "/" in iri:
        return iri.rsplit("/", 1)[-1]
    return iri

def _normalize_tid(value: str) -> str:
    """
    Normalise un identifiant de technique MITRE:
    - upper-case
    - remplace '.' par '_'
    - si IRI, ne garde que le fragment final
    """
    if not value:
        return ""
    s = value.strip()
    # extrait fragment si c’est une IRI
    s = lastfrag(s)
    # normalisation MITRE
    s = s.upper().replace(".", "_")
    return s

def _techs_from_incident(g: Graph, incident: URIRef) -> set[str]:
    """
    Récupère les techniques liées à un incident, sous forme d'IRIs normalisées (Txxxx[_yyy]).
    Sources:
      - bridge:involvesTechnique
      - bridge:hasAction / bridge:relatesToTechnique
    """
    techs: set[str] = set()

    # Direct: involvesTechnique
    for t in g.objects(incident, BRIDGE.involvesTechnique):
        techs.add(_normalize_tid(str(t)))

    # Déduit via actions
    for a in g.objects(incident, BRIDGE.hasAction):
        for t in g.objects(a, BRIDGE.relatesToTechnique):
            techs.add(_normalize_tid(str(t)))

    return techs

# ---------------------------------------------------------------------
# API principale utilisée par l'UI
# ---------------------------------------------------------------------
def get_incidents_by_tech(g: Graph, tech_ids: List[str]) -> List[str]:
    """
    Retourne la liste des incidents (IRIs) qui matchent AU MOINS une technique parmi tech_ids.
    Stratégie:
      1) Tentative SPARQL (normalisée, tolère '.' vs '_', '#' vs '/')
      2) Fallback: scan RDF complet (rapide sur nos tailles) avec normalisation Python
    """
    if not tech_ids:
        return []

    # Normalisation des T-IDs venant des alertes
    tids_norm = { _normalize_tid(t) for t in tech_ids if t }

    # --------- 1) SPARQL (tolérant) ---------
    # On compare contre les 2 extractions possibles: fragment après '#' OU après '/'
    values = " ".join(f"\"{t}\"" for t in sorted(tids_norm))
    q = f"""
    PREFIX bridge:<{BRIDGE}>
    PREFIX veris:<{VERIS}>
    SELECT DISTINCT ?incident WHERE {{
      ?incident a veris:Incident .

      OPTIONAL {{ ?incident bridge:involvesTechnique ?t1 . }}
      OPTIONAL {{ ?incident bridge:hasAction/bridge:relatesToTechnique ?t2 . }}
      BIND(COALESCE(?t1, ?t2) AS ?t)

      # Normalise côté SPARQL: extrait fragment et remplace '.' par '_'
      BIND(REPLACE(STRAFTER(STR(?t), "#"), "\\\\.", "_") AS ?h)
      BIND(REPLACE(STRAFTER(STR(?t), "/"), "\\\\.", "_") AS ?s)

      VALUES ?tid {{ {values} }}
      FILTER( LCASE(?h) = LCASE(?tid) || LCASE(?s) = LCASE(?tid) )
    }}
    """
    try:
        rows = list(g.query(q))
        if rows:
            incidents = [str(r.incident) for r in rows]
            logger.debug("SPARQL incidents=%d (matchs directs)", len(incidents))
            return incidents
    except Exception as e:
        logger.debug("SPARQL get_incidents_by_tech en échec, fallback scan: %s", e)

    # --------- 2) Fallback scan RDF ---------
    incidents_set: set[str] = set()
    for inc in g.subjects(RDF.type, VERIS.Incident):
        techs_inc = _techs_from_incident(g, inc)
        if techs_inc & tids_norm:
            incidents_set.add(str(inc))

    incidents = sorted(incidents_set)
    logger.debug("SCAN incidents=%d (matchs normalisés)", len(incidents))
    return incidents

def actions_for_incident(g: Graph, incident_iri: str) -> List[str]:
    """
    Retourne les IRIs des actions VERIS d’un incident.
    """
    q = f"""
    PREFIX bridge:<{BRIDGE}>
    SELECT DISTINCT ?a WHERE {{ <{incident_iri}> bridge:hasAction ?a . }}
    """
    try:
        return [str(r.a) for r in g.query(q)]
    except Exception as e:
        logger.debug("SPARQL actions_for_incident en échec (%s), fallback RDF scan", e)
        actions = [str(a) for a in g.objects(URIRef(incident_iri), BRIDGE.hasAction)]
        return actions

def techniques_for_incident(g: Graph, incident_iri: str) -> List[str]:
    """
    Techniques explicitement materialisées via bridge:involvesTechnique.
    """
    q = f"""
    PREFIX bridge:<{BRIDGE}>
    SELECT DISTINCT ?t WHERE {{ <{incident_iri}> bridge:involvesTechnique ?t . }}
    """
    try:
        return [str(r.t) for r in g.query(q)]
    except Exception as e:
        logger.debug("SPARQL techniques_for_incident en échec (%s), fallback RDF scan", e)
        return [str(t) for t in g.objects(URIRef(incident_iri), BRIDGE.involvesTechnique)]

def deduce_incident_techs(g: Graph, incident_iri: str) -> List[str]:
    """
    Techniques déduites via bridge:hasAction / bridge:relatesToTechnique.
    Utile si involvesTechnique n'est pas matérialisé dans l’OWL.
    """
    q = f"""
    PREFIX bridge:<{BRIDGE}>
    SELECT DISTINCT ?t WHERE {{
      <{incident_iri}> bridge:hasAction/bridge:relatesToTechnique ?t .
    }}
    """
    try:
        return [str(r.t) for r in g.query(q)]
    except Exception as e:
        logger.debug("SPARQL deduce_incident_techs en échec (%s), fallback RDF scan", e)
        out: set[str] = set()
        inc = URIRef(incident_iri)
        for a in g.objects(inc, BRIDGE.hasAction):
            for t in g.objects(a, BRIDGE.relatesToTechnique):
                out.add(str(t))
        return sorted(out)

def actions_to_tech_pairs(g: Graph, actions: List[str]) -> List[Tuple[str, str]]:
    """
    Retourne (action_iri, technique_iri) pour les actions passées.
    """
    if not actions:
        return []
    acts = " ".join(f"<{a}>" for a in actions)
    q = f"""
    PREFIX bridge:<{BRIDGE}>
    SELECT DISTINCT ?a ?t WHERE {{
      VALUES ?a {{ {acts} }}
      ?a bridge:relatesToTechnique ?t .
    }}
    """
    try:
        return [(str(r.a), str(r.t)) for r in g.query(q)]
    except Exception as e:
        logger.debug("SPARQL actions_to_tech_pairs en échec (%s), fallback RDF scan", e)
        pairs: list[tuple[str, str]] = []
        for a in actions:
            a_ref = URIRef(a)
            for t in g.objects(a_ref, BRIDGE.relatesToTechnique):
                pairs.append((a, str(t)))
        # dédoublonne proprement
        return sorted(set(pairs))
