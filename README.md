# Network Attack Path Analyzer

> **Developed by MD Jubayer Khan Akash**  
> **Project version:** 0.7.0  
> **Author / Project Owner:** MD Jubayer Khan Akash

A defensive cybersecurity lab application for modeling network topology, discovering possible attack paths, scoring their risk, simulating security changes, generating assessment reports, and producing AI-assisted explanations.

> **Authorized-use notice:** This project is a graph-based defensive analysis tool. It does not exploit real systems. Use it only with networks and data you are authorized to assess.

## What it does

- **Security-aware topology modeling** — assets, zones, criticality, exposure, services, vulnerabilities, and directional rules.
- **Attack-path discovery** — enumerates reachable source-to-target routes through allowed connections.
- **Explainable risk scoring** — combines exposure, vulnerability, criticality, service exposure, segmentation, and path complexity.
- **Interactive topology editor** — add/remove assets and model firewall/network rules from the browser.
- **What-if compromise simulation** — assume a node is compromised and measure downstream reachability and risk.
- **What-if rule simulation API** — model an allow/block policy change and compare path impact.
- **Security assessment reports** — executive metrics, top paths, severity distribution, and prioritized remediation.
- **Security Copilot** — local deterministic explanations by default, with optional OpenAI-compatible LLM integration.
- **JSON export + browser PDF workflow** — save structured reports or print the report to PDF.

## Architecture

```text
                 ┌──────────────────────────┐
                 │       Next.js UI         │
                 │ topology / analysis /    │
                 │ simulation / reports / AI │
                 └────────────┬─────────────┘
                              │ HTTP/JSON
                              ▼
                 ┌──────────────────────────┐
                 │       FastAPI API        │
                 └────────────┬─────────────┘
                              ▼
                 ┌──────────────────────────┐
                 │     Graph Builder        │
                 │ NetworkX directed graph  │
                 └────────────┬─────────────┘
                              ▼
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
  Path Engine            Risk Engine         Simulation Engine
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                    Report / AI Explanation
```

## Project structure

```text
network-attack-path-analyzer/
├── backend/
│   ├── app/
│   │   ├── api/routes.py
│   │   ├── models/schemas.py
│   │   ├── services/
│   │   │   ├── graph_engine.py
│   │   │   ├── path_engine.py
│   │   │   ├── risk_engine.py
│   │   │   ├── simulation_engine.py
│   │   │   ├── report_engine.py
│   │   │   └── ai_explainer.py
│   │   └── main.py
│   ├── tests/
│   └── requirements.txt
├── data/
│   └── sample_network.json
├── docs/
│   ├── architecture.md
│   ├── risk-model.md
│   └── roadmap.md
├── frontend/
│   ├── app/
│   │   ├── page.tsx
│   │   ├── globals.css
│   │   └── layout.tsx
│   ├── .env.example
│   └── package.json
├── .env.example
├── .gitignore
└── README.md
```

## Quick start

### 1. Backend

```bash
cd backend
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies and start the API:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

The API is available at `http://localhost:8000` and interactive API docs at `/docs`.

### 2. Frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Optional environment configuration:

```text
NEXT_PUBLIC_API_URL=http://localhost:8000
```

Then open `http://localhost:3000`.

## Core workflow

1. Select or add network assets.
2. Assign each asset a zone, criticality, exposure state, open ports, and vulnerability metadata.
3. Create directional network/firewall rules.
4. Select a source and critical target.
5. Run **Run Analysis** to discover and rank possible routes.
6. Use **Simulate Compromise** to model a compromised pivot and measure blast radius.
7. Generate a **Security Report** for remediation planning.
8. Use **AI Security Explanation** to turn structured findings into an analyst-friendly narrative.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Service health and project phase |
| POST | `/api/analyze` | Discover and rank attack paths |
| POST | `/api/simulate/compromise` | Simulate a compromised asset |
| POST | `/api/simulate/rule` | Simulate an allow/block rule change |
| POST | `/api/report` | Generate a security assessment |
| POST | `/api/ai/explain` | Explain modeled findings |

## Risk model

The analyzer uses an explainable additive model capped at 100:

- **Exposure** — externally reachable source/asset context.
- **Vulnerability** — highest modeled CVSS-like vulnerability score, weighted by path position.
- **Criticality** — business/security importance of assets on the chain.
- **Service exposure** — sensitive services such as SSH, RDP, database, Redis, SMB, and Telnet.
- **Segmentation** — crossings from lower-trust to higher-trust zones.
- **Path complexity** — additional hops, capped to avoid dominating the score.

Severity bands:

| Score | Severity |
|---:|---|
| 80–100 | Critical |
| 60–79.9 | High |
| 35–59.9 | Medium |
| 0–34.9 | Low |

The risk score is deterministic and remains the authoritative security signal. The AI layer does not alter it.

See [`docs/risk-model.md`](docs/risk-model.md) for the detailed methodology.

## What-if simulation

The compromise simulator intentionally models a **post-compromise pivot** rather than performing exploitation. It compares:

- baseline source → target paths,
- compromised asset → target paths,
- path counts,
- maximum risk before/after,
- risk delta,
- segmentation findings.

The rule simulation models a policy change on a directional edge and recalculates the route set.

## Reports and remediation

Reports contain:

- executive network metrics,
- possible path count,
- maximum and average risk,
- severity distribution,
- critical/vulnerable asset counts,
- top-ranked attack paths,
- prioritized remediation actions,
- methodology notes.

Remediations are derived from the same modeled factors used for scoring, keeping recommendations traceable to the analysis.

## Security Copilot / AI layer

The project is **local-first**. Without any AI credentials, the application generates deterministic security explanations from the graph, ranked paths, and remediation results.

Optional remote explanation can be enabled through an OpenAI-compatible chat-completions endpoint:

```text
AI_API_URL=<provider chat-completions endpoint>
AI_API_KEY=<provider key>
AI_MODEL=<model name>
```

If the remote provider is unavailable, the local explanation remains available automatically.

**Important:** never commit `.env`, `.env.local`, API keys, or other secrets. The repository ignores local environment files by default.

## Testing

From `backend/`:

```bash
pytest -q
```

The test suite covers path discovery, risk scoring, what-if simulation, and report generation. The frontend is a Next.js application; run `npm install` followed by `npm run build` locally to perform a production build.

## Limitations / future improvements

- The topology editor currently stores node positions in the browser model; it is not a full network diagramming suite.
- The current report PDF flow uses the browser print dialog rather than server-side PDF rendering.
- Remediation status persistence is not yet backed by a database.
- Multi-edge support, richer firewall semantics, VLAN/subnet modeling, authentication paths, and temporal attack graphs are possible future extensions.

## Author

**MD Jubayer Khan Akash** is the original developer and project owner of this Network Attack Path Analyzer implementation.

For portfolio and academic attribution, reference this project as:

> **Network Attack Path Analyzer — MD Jubayer Khan Akash, version 0.7.0**

## License

Add the license you prefer before publishing the repository publicly.
