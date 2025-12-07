# -*- coding: utf-8 -*-
"""
Cyber Threat Intelligent — Module alerts
Objectif: Ingestion Wazuh (JSON/NDJSON/Elasticsearch) + extraction T-IDs + métadonnées

Développeur : Lahat Fall (UQAC) — Projet-stage en cybersécurité défensive.
© 2025, Tous droits réservés.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Iterable

logger = logging.getLogger(__name__)

TID_RX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _normalize_tid(tid: str) -> str:
    """Uniformise les identifiants MITRE pour simplifier les comparaisons."""
    return tid.strip().upper().replace(".", "_")


def _iter_json(obj: object) -> Iterable[object]:
    """Parcourt récursivement un objet JSON pour expédier chaque nœud dict/list."""
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _iter_json(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_json(item)


def load_wazuh_alerts_any(text_or_obj: object) -> object:
    """
    Accepte une chaîne, du NDJSON ou un objet déjà parsé et retourne un format uniformisé.
    """
    if not isinstance(text_or_obj, (str, bytes)):
        return text_or_obj

    txt = str(text_or_obj).strip()
    if not txt:
        return {}

    lines = [line for line in txt.splitlines() if line.strip()]
    if len(lines) > 1 and all(line.strip().startswith("{") for line in lines):
        items: list[dict] = []
        for line in lines:
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                logger.debug("Ligne NDJSON ignorée (JSON invalide)")
        return {"_ndjson": items}

    data: object = json.loads(txt)
    if isinstance(data, dict) and isinstance(data.get("hits"), dict):
        hits = data["hits"].get("hits", [])
        sources = [
            hit.get("_source") for hit in hits if isinstance(hit, dict) and hit.get("_source")
        ]
        return {"_hits_sources": sources}
    return data


def _collect_tids_from_any(obj: object) -> set[str]:
    """Cherche les identifiants MITRE dans tout le JSON possible."""
    tids: set[str] = set()
    for node in _iter_json(obj):
        if not isinstance(node, dict):
            continue

        rule = node.get("rule") or {}
        mitre = rule.get("mitre") or {}
        ids = mitre.get("id")

        if isinstance(ids, str):
            tids.add(_normalize_tid(ids))
        elif isinstance(ids, list):
            for value in ids:
                if isinstance(value, (str, int)):
                    tids.add(_normalize_tid(str(value)))

        for key in ("technique", "techniques"):
            arr = mitre.get(key)
            if isinstance(arr, list):
                for technique in arr:
                    tid = technique.get("id") if isinstance(technique, dict) else technique
                    if isinstance(tid, (str, int)):
                        tids.add(_normalize_tid(str(tid)))

        for key in ("message", "description", "full_log"):
            value = node.get(key)
            if isinstance(value, str):
                for match in TID_RX.findall(value):
                    tids.add(_normalize_tid(match))

        for key in ("fields", "data"):
            sub = node.get(key)
            if isinstance(sub, dict):
                candidate = (
                    sub.get("rule", {}).get("mitre", {}).get("id")
                    or sub.get("mitre", {}).get("id")
                )
                if isinstance(candidate, str):
                    tids.add(_normalize_tid(candidate))
                elif isinstance(candidate, list):
                    for value in candidate:
                        tids.add(_normalize_tid(str(value)))
    return tids


def extract_tech_ids_universal(obj: object) -> list[str]:
    """Retourne la liste triée/unique des T-IDs trouvés."""
    tids: list[str] = []

    def extend_unique(new_items: set[str]) -> None:
        for tid in new_items:
            if tid not in tids:
                tids.append(tid)

    if isinstance(obj, dict) and "_hits_sources" in obj:
        for src in obj["_hits_sources"] or []:
            if isinstance(src, dict):
                extend_unique(_collect_tids_from_any(src))
    elif isinstance(obj, dict) and "_ndjson" in obj:
        for line in obj["_ndjson"] or []:
            if isinstance(line, dict):
                extend_unique(_collect_tids_from_any(line))
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                extend_unique(_collect_tids_from_any(item))
    elif isinstance(obj, dict):
        extend_unique(_collect_tids_from_any(obj))
    return sorted(tids)


def _first_alert_objects(obj: object) -> list[dict]:
    """Retourne les premières entrées d'alertes détectées dans n'importe quel format."""
    if isinstance(obj, dict) and "_hits_sources" in obj:
        return [item for item in obj["_hits_sources"] if isinstance(item, dict)]
    if isinstance(obj, dict) and "_ndjson" in obj:
        return [item for item in obj["_ndjson"] if isinstance(item, dict)]
    if isinstance(obj, list):
        return [item for item in obj if isinstance(item, dict)]
    return [obj] if isinstance(obj, dict) else []


def _pick_paths(data: dict, *paths: str) -> object | None:
    """Essaye plusieurs chemins imbriqués et retourne la première valeur trouvée."""
    for path in paths:
        current = data
        for key in path.split("."):
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                break
        else:
            return current
    return None


def extract_alert_metadata(obj: object) -> dict:
    """Extrait l'essentiel des métadonnées de la première alerte disponible."""
    items = _first_alert_objects(obj)
    if not items:
        return {}

    alert = items[0]
    ts = _pick_paths(alert, "@timestamp", "timestamp", "event.created", "event.ingested")
    rid = _pick_paths(alert, "rule.id")
    rdesc = _pick_paths(alert, "rule.description", "rule.full_log", "message")
    agt = _pick_paths(alert, "agent.name", "host.name")
    mids = _pick_paths(alert, "rule.mitre.id", "mitre.id")

    if isinstance(mids, str):
        mids = [mids]
    elif isinstance(mids, list):
        mids = [str(value) for value in mids]
    else:
        mids = []

    return {
        "timestamp": ts,
        "rule.id": rid,
        "rule.description": rdesc,
        "agent.name": agt,
        "rule.mitre.id": mids,
    }


def extract_all_alerts_metadata(obj: object) -> list[dict]:
    """Retourne les métadonnées pour toutes les alertes identifiées."""
    return [extract_alert_metadata(item) for item in _first_alert_objects(obj)]
