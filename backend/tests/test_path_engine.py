"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from app.models.schemas import Edge, Network, Node, Vulnerability
from app.services.graph_engine import build_graph
from app.services.path_engine import find_attack_paths


def test_risk_scoring_and_paths():
    network = Network(
        nodes=[
            Node(id="internet", name="Internet", zone="external", exposed=True, criticality=10),
            Node(id="web", name="Web", exposed=True, open_ports=[22, 443], criticality=8,
                 vulnerabilities=[Vulnerability(id="CVE-DEMO", score=8.5)]),
            Node(id="db", name="DB", type="database", criticality=10, open_ports=[3306]),
        ],
        edges=[
            Edge(source="internet", target="web", port=443),
            Edge(source="web", target="db", port=3306),
        ],
    )
    result = find_attack_paths(build_graph(network), "internet", "db")
    assert len(result) == 1
    assert result[0]["risk_score"] > 60
    assert result[0]["severity"] in {"high", "critical"}
