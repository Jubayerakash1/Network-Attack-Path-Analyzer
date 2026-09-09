"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from __future__ import annotations

from dataclasses import dataclass
import networkx as nx


SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 445: "SMB"}
ZONE_LEVEL = {"external": 0, "dmz": 1, "internal": 2, "restricted": 3}


@dataclass(frozen=True)
class RiskBreakdown:
    exposure: float
    vulnerability: float
    criticality: float
    service_exposure: float
    segmentation: float
    path_complexity: float

    @property
    def total(self) -> float:
        return min(100.0, round(self.exposure + self.vulnerability + self.criticality + self.service_exposure + self.segmentation + self.path_complexity, 1))


def severity(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _normalise_vuln_score(node: dict) -> float:
    vulns = node.get("vulnerabilities", [])
    if not vulns:
        return 0.0
    # Vulnerability score is expected to be 0-10 (CVSS-like).
    return max(float(v.get("score", 0)) for v in vulns)


def score_path(graph: nx.DiGraph, path: list[str]) -> tuple[float, list[str], dict]:
    reasons: list[str] = []
    exposure = vulnerability = criticality = service_exposure = segmentation = path_complexity = 0.0

    source = graph.nodes[path[0]]
    if source.get("exposed") or source.get("zone") == "external":
        exposure += 18
        reasons.append("Path starts from an externally reachable asset.")

    # Vulnerability and asset criticality are evaluated across the whole chain,
    # with diminishing weight for intermediate infrastructure.
    for index, node_id in enumerate(path):
        node = graph.nodes[node_id]
        weight = 1.0 if index == len(path) - 1 else 0.65
        criticality += float(node.get("criticality", 5)) * 1.6 * weight

        vuln = _normalise_vuln_score(node)
        if vuln:
            vulnerability += vuln * 3.0 * weight
            reasons.append(f"{node.get('name', node_id)} has a vulnerability score of {vuln:.1f}/10.")

        ports = set(node.get("open_ports", []))
        sensitive = sorted(p for p in ports if p in SENSITIVE_PORTS)
        if sensitive:
            service_exposure += min(12.0, len(sensitive) * 3.0 * weight)
            labels = ", ".join(f"{SENSITIVE_PORTS[p]}:{p}" for p in sensitive)
            reasons.append(f"Sensitive service exposure detected ({labels}).")

    # Crossing zone boundaries is important, but crossing into a more trusted zone
    # is more concerning than moving laterally within the same zone.
    for a, b in zip(path, path[1:]):
        za = graph.nodes[a].get("zone", "internal")
        zb = graph.nodes[b].get("zone", "internal")
        delta = ZONE_LEVEL.get(zb, 2) - ZONE_LEVEL.get(za, 2)
        if delta > 0:
            segmentation += 8 * min(delta, 2)
            reasons.append(f"Trust boundary crossed: {za} → {zb}.")
        elif za != zb:
            segmentation += 2

        edge = graph.edges[a, b]
        port = edge.get("port")
        if port in SENSITIVE_PORTS:
            reasons.append(f"Allowed edge reaches {SENSITIVE_PORTS[port]} on port {port}.")

    # Long chains increase uncertainty/attack surface, but are deliberately capped.
    path_complexity = min(8.0, max(0, len(path) - 2) * 1.5)
    if len(path) >= 5:
        reasons.append("Path contains multiple hops, increasing attack-chain complexity.")

    breakdown = RiskBreakdown(exposure, vulnerability, criticality, service_exposure, segmentation, path_complexity)
    total = breakdown.total

    if not reasons:
        reasons.append("No major risk indicators were found in the current model.")

    # Make the explanation useful to a defender.
    if vulnerability >= 12:
        reasons.append("Mitigation: prioritize patching or isolating the vulnerable asset(s) on this path.")
    if service_exposure >= 6:
        reasons.append("Mitigation: restrict unnecessary management/database services with ACLs or firewall rules.")
    if segmentation >= 6:
        reasons.append("Mitigation: strengthen segmentation and least-privilege rules across the trust boundary.")
    if exposure >= 18:
        reasons.append("Mitigation: reduce direct exposure and place internet-facing services behind hardened controls.")

    details = {
        "exposure": round(exposure, 1),
        "vulnerability": round(vulnerability, 1),
        "criticality": round(criticality, 1),
        "service_exposure": round(service_exposure, 1),
        "segmentation": round(segmentation, 1),
        "path_complexity": round(path_complexity, 1),
    }
    return total, reasons, details
