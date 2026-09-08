"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from app.models.schemas import Network
from app.services.ai_explainer import explain_security_state
from app.services.graph_engine import build_graph
from app.services.path_engine import find_attack_paths
from app.services.report_engine import generate_report


def test_local_ai_explanation_without_provider():
    network = Network(
        nodes=[
            {"id": "internet", "name": "Internet", "type": "external", "zone": "external", "criticality": 10, "exposed": True},
            {"id": "web", "name": "Web", "type": "server", "zone": "dmz", "criticality": 8, "open_ports": [443], "vulnerabilities": [{"id": "V-1", "score": 8.0}]},
            {"id": "db", "name": "DB", "type": "database", "zone": "restricted", "criticality": 10, "open_ports": [3306]},
        ],
        edges=[
            {"source": "internet", "target": "web", "port": 443, "allowed": True},
            {"source": "web", "target": "db", "port": 3306, "allowed": True},
        ],
    )
    graph = build_graph(network)
    paths = find_attack_paths(graph, "internet", "db")
    report = generate_report(graph, "internet", "db")
    result = explain_security_state(graph, "internet", "db", paths, report["remediations"])
    assert result["mode"] == "local"
    assert result["executive_summary"]
    assert result["key_risks"]
