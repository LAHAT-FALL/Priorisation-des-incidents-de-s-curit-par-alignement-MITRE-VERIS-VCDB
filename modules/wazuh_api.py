# -*- coding: utf-8 -*-
"""
Cyber Threat Intelligent — Module wazuh_api
Objectif: Client HTTP minimal Wazuh

Développeur : Lahat Fall (UQAC) — Projet-stage en cybersécurité défensive.
© 2025, Tous droits réservés.
"""
from __future__ import annotations

import logging

import requests

logger = logging.getLogger(__name__)


class WazuhClient:
    """Client HTTP minimaliste pour l'API Wazuh."""

    def __init__(
        self,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        verify_tls: bool = True,
        timeout: int = 30,
    ) -> None:
        # Prépare la configuration de session en évitant les valeurs nulles
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password) if username and password else None
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.verify = verify_tls
        self.timeout = timeout

    def get_alerts(self, params: dict | None = None) -> dict:
        """Récupère les alertes en appliquant une vérification stricte des erreurs HTTP."""
        url = f"{self.base_url}/alerts"
        r = requests.get(
            url,
            params=params,
            auth=self.auth,
            headers=self.headers,
            verify=self.verify,
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()
