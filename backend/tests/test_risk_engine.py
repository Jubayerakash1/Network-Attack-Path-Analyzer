"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from app.models.schemas import Edge, Network, Node, Vulnerability
from app.services.graph_engine import build_graph
from app.services.path_engine import find_attack_paths


def test_breakdown_contains_defensive_factors():
    network = Network(
        nodes=[
            Node(id="internet", name="Internet", zone="external", exposed=True, criticality=10),
            Node(id="web", name="Web", zone="dmz", exposed=True, criticality=8, open_ports=[22, 443], vulnerabilities=[Vulnerability(id="V1", score=8.5)]),
            Node(id="db", name="DB", type="database", zone="restricted", criticality=10, open_ports=[3306]),
        ],
        edges=[
            Edge(source="internet", target="web", port=443),
            Edge(source="web", target="db", port=3306),
        ],
    )
    result = find_attack_paths(build_graph(network), "internet", "db")
    assert result
    breakdown = result[0]["risk_breakdown"]
    assert breakdown["exposure"] > 0
    assert breakdown["vulnerability"] > 0
    assert breakdown["segmentation"] > 0
    assert 0 <= result[0]["risk_score"] <= 100


def test_compromise_simulation_reaches_database():
    from app.services.graph_engine import build_graph
    from app.services.simulation_engine import simulate_compromise
    network = {
        "nodes": [
            {"id":"web","name":"Web","type":"server","zone":"dmz","criticality":8,"exposed":True,"open_ports":[443],"vulnerabilities":[]},
            {"id":"db","name":"DB","type":"database","zone":"restricted","criticality":10,"exposed":False,"open_ports":[3306],"vulnerabilities":[]},
        ],
        "edges": [{"source":"web","target":"db","protocol":"TCP","port":3306,"allowed":True}],
    }
    result = simulate_compromise(build_graph(__import__('app.models.schemas', fromlist=['Network']).Network(**network)), "web", "db", "web")
    assert result["reachable"] is True
    assert result["post_compromise_path_count"] == 1
