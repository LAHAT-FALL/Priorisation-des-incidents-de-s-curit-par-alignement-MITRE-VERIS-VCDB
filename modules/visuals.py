# -*- coding: utf-8 -*-
"""
Cyber Threat Intelligent — Module visuals
Objectif: Schéma statique (matplotlib) — Alerte → Techniques → Actions → Incident

Développeur : Lahat Fall (UQAC) — Projet-stage en cybersécurité défensive.
© 2025, Tous droits réservés.
"""
from __future__ import annotations

import logging
from typing import List, Tuple

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.figure import Figure
from matplotlib.patches import FancyArrowPatch

logger = logging.getLogger(__name__)

BACKGROUND_COLOR = "#050912"
BORDER_COLOR = "#1e293b"
TEXT_COLOR = "#f8fafc"
TEXT_MUTED = "#cbd5f5"


def _lastfrag(text: str) -> str:
    """Retourne le fragment final d'une IRI pour faciliter l'affichage."""
    if "#" in text:
        return text.split("#", 1)[1]
    if "/" in text:
        return text.rsplit("/", 1)[-1]
    return text


def _to_mitre_iri(tid: str) -> str:
    """Génère une IRI MITRE cohérente à partir d'un T-ID libre."""
    return f"http://example.org/mitre#{tid.strip().upper().replace('.', '_')}"


def draw_chain_enriched(
    tech_ids_alert: List[str],
    pairs_action_tech: List[Tuple[str, str]],
    incident_label: str,
) -> Figure:
    """Construit le schéma statique reliant Alerte → Techniques → Actions → Incident."""
    techs_iris = sorted({tech for (_, tech) in pairs_action_tech})

    techs_alert_iris = {_to_mitre_iri(tid) for tid in (tech_ids_alert or [])}
    techs_col = [tech for tech in techs_iris if (not techs_alert_iris or tech in techs_alert_iris)]

    fig, ax = plt.subplots(figsize=(11, 6), dpi=120)
    fig.patch.set_facecolor(BACKGROUND_COLOR)
    ax.set_facecolor(BACKGROUND_COLOR)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    X_ALERT, X_TECH, X_ACT, X_INC = 0.05, 0.35, 0.65, 0.90
    Y0 = 0.85
    BOX_W, BOX_H = 0.22, 0.06
    C_ALERT, C_TECH = "#f59e0b", "#6366f1"
    C_ACT, C_INC, C_EDGE = "#22d3ee", "#ef4444", "#cbd5f5"

    alert_label = " ".join(tech_ids_alert) if tech_ids_alert else "—"
    _draw_box(ax, X_ALERT, Y0, BOX_W, BOX_H, C_ALERT, f"Alerte\n{alert_label}")

    y = Y0
    tech_pos: dict[str, tuple[float, float]] = {}
    if techs_col:
        for t in techs_col:
            y -= 0.10
            _draw_box(ax, X_TECH, y, BOX_W, BOX_H, C_TECH, _lastfrag(t))
            tech_pos[t] = (X_TECH + BOX_W / 2, y + BOX_H / 2)
            _draw_arrow(ax, (X_ALERT + BOX_W, Y0 + BOX_H / 2), (X_TECH, y + BOX_H / 2), C_EDGE)
    else:
        y -= 0.10
        _draw_box(ax, X_TECH, y, BOX_W, BOX_H, C_TECH, "—")
        tech_pos["—"] = (X_TECH + BOX_W / 2, y + BOX_H / 2)

    act_pos: dict[str, tuple[float, float]] = {}
    y_act = Y0
    acts_display: list[str] = []
    if pairs_action_tech:
        ok_techs = set(tech_pos.keys()) & set(techs_iris)
        for action, tech in sorted(pairs_action_tech):
            if tech in ok_techs and action not in acts_display:
                acts_display.append(action)

    if acts_display:
        for action in acts_display:
            y_act -= 0.10
            _draw_box(ax, X_ACT, y_act, BOX_W, BOX_H, C_ACT, _lastfrag(action))
            act_pos[action] = (X_ACT + BOX_W / 2, y_act + BOX_H / 2)
    else:
        y_act -= 0.10
        _draw_box(ax, X_ACT, y_act, BOX_W, BOX_H, C_ACT, "—")
        act_pos["—"] = (X_ACT + BOX_W / 2, y_act + BOX_H / 2)

    for action, tech in pairs_action_tech:
        if tech in tech_pos and action in act_pos:
            _draw_arrow(
                ax,
                (X_TECH + BOX_W, tech_pos[tech][1]),
                (X_ACT, act_pos[action][1]),
                C_EDGE,
            )

    _draw_box(ax, X_INC, 0.25, BOX_W, BOX_H, C_INC, f"Incident\n{incident_label}")
    for action in act_pos:
        _draw_arrow(ax, (X_ACT + BOX_W, act_pos[action][1]), (X_INC, 0.25 + BOX_H / 2), C_EDGE)

    _legend(ax, C_ALERT, C_TECH, C_ACT, C_INC)
    fig.tight_layout(pad=1.2)
    return fig


def _draw_box(
    ax: Axes,
    x_coord: float,
    y_coord: float,
    width: float,
    height: float,
    color: str,
    text: str,
) -> None:
    rect = mpatches.FancyBboxPatch(
        (x_coord, y_coord),
        width,
        height,
        boxstyle="round,pad=0.02,rounding_size=0.02",
        linewidth=1.2,
        edgecolor=BORDER_COLOR,
        facecolor=color,
        alpha=0.92,
    )
    ax.add_patch(rect)
    ax.text(
        x_coord + width / 2,
        y_coord + height / 2,
        text,
        ha="center",
        va="center",
        fontsize=10,
        color=TEXT_COLOR,
        wrap=True,
        fontweight="600",  # texte lisible pour les analystes
    )


def _draw_arrow(ax: Axes, p1: tuple[float, float], p2: tuple[float, float], color: str) -> None:
    arrow = FancyArrowPatch(
        p1,
        p2,
        arrowstyle="-|>",
        mutation_scale=12,
        linewidth=1.3,
        color=color,
        linestyle="-",
        alpha=0.85,
    )
    ax.add_patch(arrow)


def _legend(ax: Axes, c_alert: str, c_tech: str, c_act: str, c_inc: str) -> None:
    items = [
        mpatches.Patch(color=c_alert, label="Alerte"),
        mpatches.Patch(color=c_tech, label="Technique"),
        mpatches.Patch(color=c_act, label="Action"),
        mpatches.Patch(color=c_inc, label="Incident"),
    ]
    leg = ax.legend(
        handles=items,
        loc="lower left",
        facecolor=BACKGROUND_COLOR,
        edgecolor=BORDER_COLOR,
        framealpha=0.9,
    )
    for text in leg.get_texts():
        text.set_color(TEXT_MUTED)
