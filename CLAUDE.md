# CLAUDE.md — REAPER Scanner

## Your Role

You are building the **complete REAPER scanner** — engine, checks, adapters, API, frontend, database, reports, tests, and packaging. REAPER is a Python CLI vulnerability scanner purpose-built for AI agent deployments. It is to AI agents what Nessus is to networks.

This is NOT scoped to a single agent role. You build everything needed to make the scanner work end-to-end.

## Stack

- **Language:** Python 3.12+
- **CLI:** Click
- **API:** FastAPI + Uvicorn + Pydantic
- **Frontend:** Next.js (React, TypeScript, Tailwind)
- **Database:** SQLite (stdlib sqlite3 for now; ORM later if needed)
- **Reports:** JSON, SARIF (implemented); HTML, PDF (planned)
- **Distribution:** PyPI + Docker
- **Testing:** pytest, ruff

## Project Layout

```
reaper/                         # Project root
├── CLAUDE.md                   # This file
├── pyproject.toml              # Package config
├── docker-compose.yml          # Local dev stack
├── reaper/                     # Python package
│   ├── sdk.py                  # Check SDK: ReaperCheck, TargetConfig, Finding, Evidence, etc.
│   ├── engine.py               # Scanner engine: CheckLoader, ScannerEngine, ScanResult
│   ├── cli.py                  # CLI: scan, probe, list-checks, validate-check
│   ├── models/                 # Data models for recon, catalog, scan state, discovery, classification
│   ├── transport/              # MCP transport layer (stdio, SSE)
│   ├── adapters/               # Framework adapters
│   │   ├── base.py             # Abstract: discover_agents(), build_target()
│   │   ├── openclaw.py         # OpenClaw adapter
│   │   └── mcp_generic.py      # Generic MCP adapter
│   └── report/                 # Report generators
│       ├── json_report.py      # JSON output
│       └── sarif.py            # SARIF v2.1.0 output
├── api/                        # FastAPI backend
│   ├── main.py                 # App entry, CORS, router mounts
│   ├── routers/                # API endpoints
│   └── schemas/                # Pydantic request/response models
├── frontend/                   # Next.js UI
├── checks/                     # Detection check modules
├── fixtures/                   # Test fixtures per check
└── tests/                      # Test suite
```

## Two Scan Wedges

| Wedge | Name | Scope | Status |
|-------|------|-------|--------|
| 1 | Config Scanner | Static config analysis — no running agent needed | Active |
| 2 | Infra Prober | Active probing of MCP server endpoints | Active |
| 3 | Runtime Analyzer | Dynamic testing against running agents | Planned |

## Check Contract (Summary)

- **detect() is a pure function.** No filesystem, no network. All data via `TargetConfig`. Returns `Finding | None`.
- **probe() is for active checks.** Connects to MCP servers via transport layer. Returns `Finding | None`.
- **Taxonomy required.** Primary = `owasp_asi` (ASI01–ASI10). Secondary MITRE ATLAS and CWE when applicable.
- **Fixtures required.** Per framework: 3 vulnerable, 3 safe, 2 borderline.
- **No third-party imports** in check modules. Only stdlib + `reaper.sdk`.
- **Severity assessed against worst-case** agentic deployment (autonomy=1.0, tools=1.0).
- **Remediation must be copy-pasteable** per framework.

## Behavioral Rules

1. **Think before coding.** State assumptions. If uncertain, ask. Surface tradeoffs.
2. **Simplicity first.** Minimum code that solves the problem. No speculative abstractions.
3. **Surgical changes.** Touch only what you must. Match existing style.
4. **Goal-driven execution.** Define success criteria, verify after each step.

## Verification

```bash
pytest tests/ -x -v
ruff check .
```
