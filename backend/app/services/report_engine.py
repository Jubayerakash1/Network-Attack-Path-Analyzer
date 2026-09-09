"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from __future__ import annotations

from collections import Counter
import networkx as nx

from app.services.path_engine import find_attack_paths


def build_remediations(graph: nx.DiGraph, paths: list[dict]) -> list[dict]:
    items = []
    seen = set()
    for path_result in paths:
        path = path_result["path"]
        breakdown = path_result["risk_breakdown"]
        for node_id in path:
            node = graph.nodes[node_id]
            vulns = node.get("vulnerabilities", [])
            if vulns:
                key = ("patch", node_id)
                if key not in seen:
                    seen.add(key)
                    items.append({"priority": "critical" if max(v.get("score", 0) for v in vulns) >= 8 else "high", "category": "Vulnerability", "asset": node.get("name", node_id), "action": "Patch, upgrade, or isolate the vulnerable asset and validate remediation with a follow-up assessment."})
            sensitive = [p for p in node.get("open_ports", []) if p in {22,23,445,3306,3389,5432,6379}]
            if sensitive:
                key = ("service", node_id, tuple(sorted(sensitive)))
                if key not in seen:
                    seen.add(key)
                    items.append({"priority": "high", "category": "Service exposure", "asset": node.get("name", node_id), "action": f"Restrict unnecessary exposed services ({', '.join(map(str, sorted(sensitive)))}) using host firewall, ACL, or network policy."})
        if breakdown["segmentation"] >= 6:
            key = ("segmentation", tuple(path))
            if key not in seen:
                seen.add(key)
                items.append({"priority": "high", "category": "Segmentation", "asset": " → ".join(path), "action": "Review the trust-boundary rule and enforce least-privilege access between zones."})
        if breakdown["exposure"] >= 18:
            key = ("exposure", tuple(path))
            if key not in seen:
                seen.add(key)
                items.append({"priority": "high", "category": "External exposure", "asset": graph.nodes[path[0]].get("name", path[0]), "action": "Minimize direct internet exposure and place public services behind hardened reverse-proxy, WAF, VPN, or equivalent controls where appropriate."})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(items, key=lambda x: (order[x["priority"]], x["category"], x["asset"]))


def generate_report(graph: nx.DiGraph, source: str, target: str, max_paths: int = 20) -> dict:
    paths = find_attack_paths(graph, source, target, max_paths)
    scores = [p["risk_score"] for p in paths]
    severity_counts = Counter(p["severity"] for p in paths)
    top = paths[:5]
    remediations = build_remediations(graph, paths)
    return {
        "title": "Network Attack Path Security Assessment",
        "source": source,
        "target": target,
        "summary": {
            "nodes": graph.number_of_nodes(),
            "allowed_edges": graph.number_of_edges(),
            "possible_paths": len(paths),
            "max_risk": round(max(scores), 1) if scores else 0.0,
            "average_risk": round(sum(scores) / len(scores), 1) if scores else 0.0,
            "severity_counts": dict(severity_counts),
            "critical_assets": sum(1 for _, d in graph.nodes(data=True) if d.get("criticality", 0) >= 9),
            "vulnerable_assets": sum(1 for _, d in graph.nodes(data=True) if d.get("vulnerabilities")),
        },
        "top_paths": top,
        "remediations": remediations,
        "methodology": [
            "Attack paths are enumerated on allowed directed edges.",
            "Risk combines exposure, vulnerability severity, asset criticality, sensitive services, segmentation, and path complexity.",
            "Findings are recommendations for authorized defensive assessment; no exploitation is performed.",
        ],
    }
