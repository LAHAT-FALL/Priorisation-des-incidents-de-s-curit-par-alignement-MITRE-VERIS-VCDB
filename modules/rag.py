# -*- coding: utf-8 -*-
"""
Cyber Threat Intelligent — Module rag
Objectif: Fournir un mini-RAG local basé sur pondération cosine bag-of-words.

Développeur : Lahat Fall (UQAC) — Projet-stage en cybersécurité défensive.
© 2025, Tous droits réservés.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List

TOKEN_RX = re.compile(r"[\w-]+", re.UNICODE)


def _tokenize(text: str) -> List[str]:
    """Découpe un texte en tokens basiques (letters/chiffres)."""
    if not text:
        return []
    return [tok.lower() for tok in TOKEN_RX.findall(text)]


def _norm(counter: Counter) -> float:
    """Calcule la norme euclidienne d'un vecteur pour éviter les divisions par zéro."""
    return math.sqrt(sum(v * v for v in counter.values())) or 1.0


def _cosine(vec_a: Counter, norm_a: float, vec_b: Counter, norm_b: float) -> float:
    """Renvoie la similarité cosinus entre deux représentations bag-of-words."""
    if not vec_a or not vec_b:
        return 0.0
    score = 0.0
    for token, value in vec_a.items():
        if token in vec_b:
            score += value * vec_b[token]
    return score / (norm_a * norm_b) if score else 0.0


def _snippet(text: str, limit: int = 260) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut + "…"


@dataclass
class RagResult:
    title: str
    content: str
    snippet: str
    score: float


class SimpleRAG:
    """Index très léger basé sur TF-idf ponctuel (bag-of-words normalisé)."""

    def __init__(self, documents: Iterable[Dict[str, str]]) -> None:
        self.docs: List[Dict[str, str]] = []
        self.vectors: List[Counter] = []
        self.norms: List[float] = []
        for doc in documents:
            title = (doc.get("title") or "Section").strip()
            content = (doc.get("content") or "").strip()
            self.docs.append({"title": title, "content": content})
            vec = Counter(_tokenize(content))
            self.vectors.append(vec)
            self.norms.append(_norm(vec))

    def search(self, query: str, top_k: int = 3) -> List[Dict[str, str]]:
        """Recherche les passages les plus pertinents en appliquant un cut-off sécurisé."""
        if not self.docs:
            return []
        q_vec = Counter(_tokenize(query))
        q_norm = _norm(q_vec)
        scored: List[RagResult] = []
        for doc, vec, norm in zip(self.docs, self.vectors, self.norms, strict=False):
            sim = _cosine(q_vec, q_norm, vec, norm)
            if sim > 0:
                scored.append(
                    RagResult(
                        title=doc["title"],
                        content=doc["content"],
                        snippet=_snippet(doc["content"]),
                        score=sim,
                    )
                )
        if not scored and self.docs:
            fallback_doc = self.docs[0]
            scored.append(
                RagResult(
                    title=fallback_doc["title"],
                    content=fallback_doc["content"],
                    snippet=_snippet(fallback_doc["content"]),
                    score=0.0,
                )
            )
        scored.sort(key=lambda r: r.score, reverse=True)
        top = scored[: top_k or 1]
        return [r.__dict__ for r in top]
