# Architecture

## Frontend

Next.js + React provides the defensive analyst workspace:

- topology editor
- asset inspector
- connection builder
- source/target selection
- ranked path results
- compromise simulation
- security report view
- Security Copilot explanation

The frontend sends the current topology as JSON to the FastAPI backend. Node coordinates used for the SVG view are stripped before analysis.

## Backend

FastAPI exposes the analysis and simulation APIs. Pydantic models validate the network schema before graph processing.

### Graph Builder

`graph_engine.py` converts the validated network into a directed NetworkX graph. Blocked edges are excluded from the analysis graph.

### Path Engine

`path_engine.py` enumerates simple directed source-to-target routes and attaches explainable risk results to each path.

### Risk Engine

`risk_engine.py` calculates the deterministic risk breakdown and severity. It is the authoritative scoring layer.

### Simulation Engine

`simulation_engine.py` copies the graph for what-if analysis so modeled changes do not mutate the user's baseline topology.

### Report Engine

`report_engine.py` converts the same structured analysis into an assessment report and remediation recommendations.

### AI Explainer

`ai_explainer.py` produces a deterministic local explanation first. An optional OpenAI-compatible provider can add an LLM narrative without changing the numeric risk model.
