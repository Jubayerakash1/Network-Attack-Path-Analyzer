"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from app.services.graph_engine import build_graph
from app.services.report_engine import generate_report
from app.models.schemas import Network


def test_report_contains_remediation_and_summary():
    network = Network.model_validate({
        "nodes": [
            {"id": "internet", "name": "Internet", "type": "external", "zone": "external", "criticality": 10, "exposed": True},
            {"id": "web", "name": "Web", "type": "server", "zone": "dmz", "criticality": 8, "exposed": True, "open_ports": [443], "vulnerabilities": [{"id": "V-1", "score": 8.5}]},
            {"id": "db", "name": "DB", "type": "database", "zone": "restricted", "criticality": 10, "open_ports": [3306]},
        ],
        "edges": [
            {"source": "internet", "target": "web", "port": 443, "allowed": True},
            {"source": "web", "target": "db", "port": 3306, "allowed": True},
        ],
    })
    report = generate_report(build_graph(network), "internet", "db")
    assert report["summary"]["possible_paths"] == 1
    assert report["summary"]["max_risk"] > 0
    assert report["remediations"]
