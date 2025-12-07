from modules.ontology import get_incidents_by_tech
from rdflib import Graph


def test_incidents_empty_graph() -> None:
    g = Graph()
    assert get_incidents_by_tech(g, ["T1190"]) == []
