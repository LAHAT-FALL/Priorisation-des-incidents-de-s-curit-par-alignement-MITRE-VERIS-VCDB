# Priorisation-des-incidents-de-s-curit-par-alignement-MITRE-VERIS-VCDB
# Cyber Threat Intelligent (CTI)
Plate-forme d’intelligence SOC qui corrèle automatiquement des alertes Wazuh avec les référentiels **MITRE ATT&CK**, **VERIS** et **VCDB**, alimente une chaîne sémantique visuelle et produit un rapport HTML enrichi d’une analyse LLM locale.

Développé par **Lahat Fall (UQAC)** dans le cadre d’un projet-stage en cybersécurité défensive — © 2025.

---

## Sommaire
- [Cyber Threat Intelligent (CTI)](#cyber-threat-intelligent-cti)
  - [Sommaire](#sommaire)
  - [Objectifs](#objectifs)
  - [Architecture \& modules](#architecture--modules)
  - [Installation \& prérequis](#installation--prérequis)
    - [Dépendances Python](#dépendances-python)
  - [Lancement rapide](#lancement-rapide)
  - [Fonctionnalités majeures](#fonctionnalités-majeures)
  - [Mode RAG + LLM](#mode-rag--llm)
  - [Rapports \& exports](#rapports--exports)
  - [Performances \& sécurité](#performances--sécurité)
  - [Importance SOC \& perspectives](#importance-soc--perspectives)
    - [Pourquoi cette plate-forme est critique pour un SOC](#pourquoi-cette-plate-forme-est-critique-pour-un-soc)
    - [Perspectives du projet](#perspectives-du-projet)
  - [Structure du dépôt](#structure-du-dépôt)
  - [Crédits \& licence](#crédits--licence)

---

## Objectifs
- **Corrélation interprétable** : établir et justifier la chaîne _Alerte → Techniques MITRE → Actions VERIS → Incident_.
- **Centralisation des connaissances** : exploiter une ontologie OWL (MITRE ↔ VERIS ↔ VCDB) et un mini-RAG local pour contextualiser chaque analyse.
- **Automatisation SOC** : proposer un tableau de bord Streamlit, un générateur de rapports HTML et une intégration LLM (Ollama) qui reste 100 % locale.

## Architecture & modules
| Module | Rôle |
| --- | --- |
| `modules/alerts.py` | Ingestion d’alertes Wazuh (JSON/NDJSON/API) + extraction universelle des T-IDs. |
| `modules/ontology.py` | Interrogations RDF/SPARQL, mapping _incidents ↔ actions ↔ techniques_. |
| `modules/visuals.py` | Diagramme statique “Alerte → Techniques → Actions → Incident” (thème sombre). |
| `modules/llm.py` | Wrapper Ollama + génération de prompt avec contexte auto + extraits RAG. |
| `modules/rag.py` | Mini moteur RAG (bag-of-words/cosine) sur la documentation embarquée. |
| `modules/report.py` | Générateur de rapport HTML (métriques synthétiques, sections MITRE/VERIS, bloc LLM). |

## Installation & prérequis
1. **Python** ≥ 3.11 + `pip`
2. **Ollama** installé localement avec le modèle `llama3.2:1b` (par défaut). Exemple :
   ```bash
   ollama pull llama3.2:1b
   ```
3. (Optionnel) watchdog/uvicorn/etc. pour un déploiement containerisé.

### Dépendances Python
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Lancement rapide
```bash
streamlit run streamlit_app.py
```

Le tableau de bord charge automatiquement :
- l’ontologie OWL définie dans `config.yaml` (`owl_file`),
- une alerte exemple (`alert_file`).

## Fonctionnalités majeures
- **Dashboard multi-onglets** : Accueil, Tableau de bord, Incidents, Détail incident, Flux d’alertes, Paramètres, Documentation.
- **Filtrage avancé des incidents** : recherche textuelle, seuil minimum d’actions, sélection persistante.
- **Chaîne sémantique statique optimisée** : diagramme couleur (Matplotlib) toujours visible, adaptable aux écrans étroits, exportable depuis Streamlit.
- **Aperçu JSON & métadonnées** : prévisualisation des alertes importées, tableau des données extraites.
- **RAG + LLM local** : la partie “Analyse & recommandations” exploite un contexte auto + extraits documentaires pertinents, puis appelle Ollama.
- **Rapport HTML** : métriques, sections MITRE/VERIS, incident, analyse LLM (ou mention d’absence), prêt à être archivé ou partagé.

## Mode RAG + LLM
- La documentation interne (`DOC_SECTIONS_DATA`) est indexée à chaud par le module `SimpleRAG`.
- Lors d’une analyse, les mots-clés (incident, T-IDs, actions, notes analyste) servent de requête pour récupérer les passages les plus pertinents.
- Ces extraits sont affichés dans l’UI et injectés dans le prompt via `knowledge_chunks`, garantissant des réponses contextualisées tout en restant locales.

## Rapports & exports
- **HTML autonome** : généré via `modules/report.py`, contient logo, métriques, sections MITRE/VERIS, incident, bloc LLM.
- **Téléchargement Streamlit** : bouton “📥 Télécharger le rapport (HTML)” disponible dans l’onglet Détail incident.
- **Personnalisation** : modifier `modules/report.py` pour ajuster la charte, ajouter un logo spécifique ou intégrer d’autres sections.

## Performances & sécurité
- **UI responsive** : la grille des KPI, les panneaux et les tableaux réagissent aux petits écrans (media queries embarquées) pour garder l’app confortable sur laptop/tablette.
- **Chaîne graphique allégée** : PyVis a été retiré pour éviter le chargement de bibliothèques lourdes ; seul le rendu statique est conservé.
- **Caching Streamlit** : l’ontologie RDF (`load_graph`) et l’extraction d’incident sont conservées en mémoire pour éviter les rechargements.
- **Qualité de code** : exécuter `ruff check modules streamlit_app.py tests` et `bandit -r modules streamlit_app.py` pour vérifier PEP8 + règles DevSecOps.
- **LLM local uniquement** : aucun appel externe n’est effectué ; vérifier la configuration `config.yaml` pour activer/désactiver l’appel Ollama.

## Importance SOC & perspectives
### Pourquoi cette plate-forme est critique pour un SOC
- **Visibilité bout-en-bout** : chaque alerte Wazuh est immédiatement reliée à des techniques MITRE, des actions VERIS et un incident documenté, ce qui réduit le temps d’investigation.
- **Traçabilité documentaire** : le rapport HTML et l’explication LLM fournissent un artefact prêt à être archivé dans un ticketing SOC ou partagé avec une équipe CERT.
- **Isolation des données** : les flux MITRE/VERIS/LLM restent sur site (aucune dépendance cloud), ce qui répond aux contraintes de confidentialité des SOC sensibles.
- **Uniformisation des analyses** : la normalisation robuste des T-IDs et l’ontologie assurent une interprétation homogène, même lorsque les analystes changent d’équipe ou de shift.

### Perspectives du projet
- **Intégration multi-SIEM** : étendre l’ingestion à d’autres sources (Elastic, Splunk, Sentinel) pour couvrir une surface SOC plus large.
- **Renforcement du moteur RAG** : ajouter des corpus spécifiques (playbooks internes, politiques de réponse) et proposer un filtrage par classification (impact/criticité).
- **Automatisation enrichie** : générer automatiquement les tickets d’incident (ServiceNow/JIRA) ou pousser le rapport HTML vers un dépôt Git sécurisé.
- **Déploiement conteneurisé** : proposer un chart Helm / image Docker officielle pour faciliter l’intégration dans des SOC hybrides.
- **Tests et monitoring** : ajouter des suites de tests e2e et un healthcheck pour intégrer l’app dans un pipeline CI/CD SOC.

## Structure du dépôt
```
.
├── assets/                 # Logo, images UI
├── data/                   # Ontologie OWL + alerte d’exemple
├── modules/
│   ├── alerts.py
│   ├── llm.py
│   ├── ontology.py
│   ├── rag.py
│   ├── report.py
│   ├── visuals.py
│   └── …
├── streamlit_app.py        # App principale (UI + logique)
├── requirements.txt
└── README.md               # Vous y êtes
```

## Crédits & licence
- **Auteur** : Lahat Fall — Université du Québec à Chicoutimi (UQAC).
- **Encadrement** : projet-stage en cybersécurité défensive (Automne 2025).
- **Licence** : Tous droits réservés — reproduction ou redistribution interdite sans accord explicite.

Pour toute question ou collaboration, contactez l’équipe UQAC ou ouvrez une issue sur le dépôt associé.
