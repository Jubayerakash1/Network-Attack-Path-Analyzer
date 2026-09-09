"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    id: str
    severity: str = "medium"
    score: float = Field(default=5.0, ge=0, le=10)
    description: str = ""


class Node(BaseModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    type: str = "host"
    zone: str = "internal"
    criticality: int = Field(default=5, ge=1, le=10)
    exposed: bool = False
    open_ports: list[int] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class Edge(BaseModel):
    source: str
    target: str
    protocol: str = "TCP"
    port: int | None = Field(default=None, ge=1, le=65535)
    allowed: bool = True
    description: str = ""


class Network(BaseModel):
    nodes: list[Node]
    edges: list[Edge]


class AnalyzeRequest(BaseModel):
    network: Network
    source: str
    target: str
    max_paths: int = Field(default=20, ge=1, le=1000)


class RiskBreakdown(BaseModel):
    exposure: float
    vulnerability: float
    criticality: float
    service_exposure: float
    segmentation: float
    path_complexity: float


class PathResult(BaseModel):
    path: list[str]
    hops: int
    rank: int
    risk_score: float
    severity: str
    reasons: list[str]
    risk_breakdown: RiskBreakdown


class AnalyzeResponse(BaseModel):
    source: str
    target: str
    total_paths: int
    paths: list[PathResult]


class SimulationRequest(BaseModel):
    network: Network
    source: str
    target: str
    compromised: str
    max_paths: int = Field(default=20, ge=1, le=1000)


class SimulationResponse(BaseModel):
    compromised: str
    target: str
    reachable: bool
    baseline_path_count: int
    post_compromise_path_count: int
    baseline_max_risk: float
    post_compromise_max_risk: float
    risk_delta: float
    paths: list[PathResult]
    findings: list[str]


class RuleSimulationRequest(BaseModel):
    network: Network
    source: str
    target: str
    edge_source: str
    edge_target: str
    allowed: bool
    max_paths: int = Field(default=20, ge=1, le=1000)


class RuleSimulationResponse(BaseModel):
    edge: dict
    baseline_path_count: int
    post_change_path_count: int
    baseline_max_risk: float
    post_change_max_risk: float
    risk_delta: float
    paths: list[PathResult]


class ReportRequest(BaseModel):
    network: Network
    source: str
    target: str
    max_paths: int = Field(default=20, ge=1, le=1000)


class ReportResponse(BaseModel):
    title: str
    source: str
    target: str
    summary: dict
    top_paths: list[PathResult]
    remediations: list[dict]
    methodology: list[str]


class AIExplainRequest(BaseModel):
    network: Network
    source: str
    target: str
    max_paths: int = Field(default=20, ge=1, le=1000)


class AIExplainResponse(BaseModel):
    mode: str
    executive_summary: str
    threat_story: str
    key_risks: list[dict]
    priority_actions: list[dict]
    analyst_notes: list[str]
    llm_explanation: str | None = None
