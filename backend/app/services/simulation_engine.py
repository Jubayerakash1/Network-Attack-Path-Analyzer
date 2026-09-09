"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from __future__ import annotations

import networkx as nx
from app.services.path_engine import find_attack_paths
from app.services.risk_engine import score_path


def simulate_compromise(graph: nx.DiGraph, source: str, target: str, compromised: str, max_paths: int = 20) -> dict:
    if compromised not in graph:
        raise ValueError(f"Unknown compromised node: {compromised}")
    if source not in graph or target not in graph:
        raise ValueError("Source or target node does not exist")

    baseline = find_attack_paths(graph, source, target, max_paths)

    # What-if model: once an asset is compromised, treat it as an attacker-controlled
    # pivot. Analyze reachability from that pivot to the target and score the resulting paths.
    pivot_paths = find_attack_paths(graph, compromised, target, max_paths)
    reachable = bool(pivot_paths)

    before_max = max((p["risk_score"] for p in baseline), default=0.0)
    after_max = max((p["risk_score"] for p in pivot_paths), default=0.0)
    before_count = len(baseline)
    after_count = len(pivot_paths)

    return {
        "compromised": compromised,
        "target": target,
        "reachable": reachable,
        "baseline_path_count": before_count,
        "post_compromise_path_count": after_count,
        "baseline_max_risk": before_max,
        "post_compromise_max_risk": after_max,
        "risk_delta": round(after_max - before_max, 1),
        "paths": pivot_paths,
        "findings": _findings(graph, compromised, target, pivot_paths),
    }


def simulate_rule_change(graph: nx.DiGraph, source: str, target: str, edge_source: str, edge_target: str, allowed: bool, max_paths: int = 20) -> dict:
    if not graph.has_node(edge_source) or not graph.has_node(edge_target):
        raise ValueError("Rule source or target node does not exist")

    baseline = find_attack_paths(graph, source, target, max_paths)
    modified = graph.copy()
    if modified.has_edge(edge_source, edge_target):
        modified.edges[edge_source, edge_target]["allowed"] = allowed
    elif allowed:
        modified.add_edge(edge_source, edge_target, protocol="TCP", port=None, allowed=True, description="What-if rule")

    if not allowed and modified.has_edge(edge_source, edge_target):
        modified.remove_edge(edge_source, edge_target)

    after = find_attack_paths(modified, source, target, max_paths)
    before_max = max((p["risk_score"] for p in baseline), default=0.0)
    after_max = max((p["risk_score"] for p in after), default=0.0)
    return {
        "edge": {"source": edge_source, "target": edge_target, "allowed": allowed},
        "baseline_path_count": len(baseline),
        "post_change_path_count": len(after),
        "baseline_max_risk": before_max,
        "post_change_max_risk": after_max,
        "risk_delta": round(after_max - before_max, 1),
        "paths": after,
    }


def _findings(graph: nx.DiGraph, compromised: str, target: str, paths: list[dict]) -> list[str]:
    node = graph.nodes[compromised]
    findings = [f"Assume {node.get('name', compromised)} is already compromised and attacker-controlled."]
    if paths:
        findings.append(f"The compromised asset can reach {graph.nodes[target].get('name', target)} through {len(paths)} modeled path(s).")
        zones = [graph.nodes[p]["zone"] for p in paths[0]["path"] if p in graph.nodes]
        if len(set(zones)) > 1:
            findings.append("The pivot crosses network trust zones; review segmentation and least-privilege ACLs.")
    else:
        findings.append("No modeled path from the compromised asset to the selected target was found.")
    return findings
