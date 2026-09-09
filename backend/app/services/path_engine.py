"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

import networkx as nx

from app.services.risk_engine import score_path, severity


def find_attack_paths(graph: nx.DiGraph, source: str, target: str, max_paths: int = 20) -> list[dict]:
    if source not in graph:
        raise ValueError(f"Unknown source node: {source}")
    if target not in graph:
        raise ValueError(f"Unknown target node: {target}")

    if source == target:
        risk, reasons, breakdown = score_path(graph, [source])
        return [{"path": [source], "hops": 0, "rank": 1, "risk_score": risk, "severity": severity(risk), "reasons": reasons, "risk_breakdown": breakdown}]

    scored = []
    for path in nx.all_simple_paths(graph, source=source, target=target):
        risk, reasons, breakdown = score_path(graph, path)
        scored.append((risk, len(path) - 1, path, reasons, breakdown))

    scored.sort(key=lambda item: (-item[0], item[1], item[2]))
    scored = scored[:max_paths]

    return [
        {
            "path": path,
            "hops": hops,
            "rank": index,
            "risk_score": risk,
            "severity": severity(risk),
            "reasons": reasons,
            "risk_breakdown": breakdown,
        }
        for index, (risk, hops, path, reasons, breakdown) in enumerate(scored, start=1)
    ]
