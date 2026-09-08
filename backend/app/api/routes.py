"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from fastapi import APIRouter, HTTPException

from app.models.schemas import AnalyzeRequest, AnalyzeResponse, SimulationRequest, SimulationResponse, RuleSimulationRequest, RuleSimulationResponse, ReportRequest, ReportResponse, AIExplainRequest, AIExplainResponse
from app.services.graph_engine import build_graph
from app.services.path_engine import find_attack_paths
from app.services.simulation_engine import simulate_compromise, simulate_rule_change
from app.services.report_engine import generate_report
from app.services.ai_explainer import explain_security_state

router = APIRouter(prefix="/api", tags=["analysis"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "phase": "7"}


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    try:
        graph = build_graph(request.network)
        paths = find_attack_paths(graph, request.source, request.target, request.max_paths)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return AnalyzeResponse(source=request.source, target=request.target, total_paths=len(paths), paths=paths)


@router.post("/simulate/compromise", response_model=SimulationResponse)
def compromise_simulation(request: SimulationRequest) -> SimulationResponse:
    try:
        graph = build_graph(request.network)
        result = simulate_compromise(graph, request.source, request.target, request.compromised, request.max_paths)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return SimulationResponse(**result)


@router.post("/simulate/rule", response_model=RuleSimulationResponse)
def rule_simulation(request: RuleSimulationRequest) -> RuleSimulationResponse:
    try:
        graph = build_graph(request.network)
        result = simulate_rule_change(graph, request.source, request.target, request.edge_source, request.edge_target, request.allowed, request.max_paths)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RuleSimulationResponse(**result)


@router.post("/report", response_model=ReportResponse)
def report(request: ReportRequest) -> ReportResponse:
    try:
        graph = build_graph(request.network)
        result = generate_report(graph, request.source, request.target, request.max_paths)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ReportResponse(**result)


@router.post("/ai/explain", response_model=AIExplainResponse)
def ai_explain(request: AIExplainRequest) -> AIExplainResponse:
    try:
        graph = build_graph(request.network)
        paths = find_attack_paths(graph, request.source, request.target, request.max_paths)
        report = generate_report(graph, request.source, request.target, request.max_paths)
        result = explain_security_state(graph, request.source, request.target, paths, report["remediations"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AIExplainResponse(**result)
