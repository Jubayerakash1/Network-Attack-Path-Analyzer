"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from __future__ import annotations

from collections import Counter
import os
import urllib.request
import json
import networkx as nx


def _deterministic_explanation(graph: nx.DiGraph, source: str, target: str, paths: list[dict], remediations: list[dict]) -> dict:
    if not paths:
        return {
            "mode": "local",
            "executive_summary": f"No modeled attack path currently connects {source} to {target}. This indicates the present directed allow-rules prevent reachability in the modeled topology.",
            "threat_story": "The selected target is not reachable under the current network policy. Continue validating that the model matches the real control plane and monitor for configuration drift.",
            "key_risks": [],
            "priority_actions": [],
            "analyst_notes": ["This explanation is generated from the topology and risk model; it does not claim that a real system is secure."]
        }

    highest = paths[0]
    counts = Counter(p["severity"] for p in paths)
    key_risks = []
    for factor, label in [
        ("vulnerability", "Vulnerability exposure"),
        ("service_exposure", "Sensitive service exposure"),
        ("segmentation", "Segmentation weakness"),
        ("exposure", "External exposure"),
        ("criticality", "Critical asset impact"),
    ]:
        value = highest["risk_breakdown"].get(factor, 0)
        if value > 0:
            key_risks.append({"factor": label, "score": value, "why": f"This factor contributes {value:.1f} points to the highest-ranked path."})

    priority_actions = []
    for item in remediations[:5]:
        priority_actions.append({"priority": item["priority"], "action": item["action"], "asset": item["asset"]})

    path_names = " → ".join(graph.nodes[n].get("name", n) for n in highest["path"])
    return {
        "mode": "local",
        "executive_summary": f"The highest-ranked modeled route is {path_names}. Its risk is {highest['risk_score']}/100 ({highest['severity']}). The model contains {len(paths)} possible route(s), with severity distribution: {dict(counts)}.",
        "threat_story": f"A defensive analyst should investigate the chain {path_names}. The route becomes more concerning where exposed services, vulnerable assets, sensitive ports, or trust-boundary crossings combine with a high-value target. The current result is a model-based risk assessment, not evidence of exploitation.",
        "key_risks": key_risks,
        "priority_actions": priority_actions,
        "analyst_notes": [
            "Prioritize controls that reduce the highest-scoring risk factors rather than only reducing hop count.",
            "Re-run the analyzer after remediation to verify that the risky route is removed or materially reduced.",
            "Use the What-if simulator to validate firewall and segmentation changes before applying them to production."
        ]
    }


def _try_remote_llm(prompt: str) -> str | None:
    """Optional OpenAI-compatible endpoint. Disabled unless explicitly configured."""
    url = os.getenv("AI_API_URL")
    key = os.getenv("AI_API_KEY")
    model = os.getenv("AI_MODEL", "gpt-4.1-mini")
    if not url or not key:
        return None
    payload = json.dumps({"model": model, "messages": [{"role": "system", "content": "You are a defensive cybersecurity analyst. Explain modeled network risk without giving exploitation instructions."}, {"role": "user", "content": prompt}], "temperature": 0.2}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            data = json.loads(response.read().decode())
        return data["choices"][0]["message"]["content"]
    except Exception:
        return None


def explain_security_state(graph: nx.DiGraph, source: str, target: str, paths: list[dict], remediations: list[dict]) -> dict:
    result = _deterministic_explanation(graph, source, target, paths, remediations)
    # The local explanation is always retained as a safe fallback. A configured
    # provider can add a prose interpretation, but the numeric risk model remains authoritative.
    if os.getenv("AI_API_URL") and os.getenv("AI_API_KEY") and paths:
        prompt = json.dumps({"source": source, "target": target, "top_paths": paths[:5], "remediations": remediations[:5]})
        remote = _try_remote_llm(prompt)
        if remote:
            result["mode"] = "remote-llm"
            result["llm_explanation"] = remote
    return result
