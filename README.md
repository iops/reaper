# REAPER

**AI Agent Vulnerability Scanner**

REAPER is to AI agents what Nessus is to networks. It scans agent configurations, tool permissions, and MCP server deployments for security weaknesses — before attackers find them.

```bash
pip install reaper-scanner
reaper scan /path/to/agent
```

```
Loaded 7 checks
[mcp_generic] Found 1 agent(s)
  my-agent: 2 findings (4ms)
```

## What It Finds

REAPER detects misconfigurations and security gaps across AI agent deployments:

| Check ID | Severity | What It Detects |
|----------|----------|-----------------|
| RPR-CONF-001 | High | MCP servers configured without authentication |
| RPR-CONF-002 | High | Tools with missing or overly broad permission scopes |
| RPR-CONF-003 | Critical | Authentication and authorization config gaps |
| RPR-CONF-005 | High | Scope boundary and isolation failures between tools |
| RPR-CONF-006 | High | Missing logging, monitoring, or human-in-the-loop gates |
| RPR-CONF-008 | High | Cross-tool privilege escalation risk patterns |
| RPR-INFRA-001 | Critical | MCP servers that accept unauthenticated connections at runtime |

Every finding maps to [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/) (ASI 2026) and relevant CWEs.

## Two Scanning Modes

**Wedge 1 — Static Configuration Analysis**
Examines agent config files, tool declarations, and MCP server setups without needing a running agent. Pure static analysis, deterministic results.

```bash
reaper scan /path/to/agent --output json
```

**Wedge 2 — Active Infrastructure Probing**
Connects to live MCP server endpoints and verifies that security controls are actually enforced at runtime. Tests unauthenticated access, invalid credentials, and unauthorized tool invocation.

```bash
reaper probe "python server.py" --transport stdio
```

## Installation

Requires Python 3.12+.

```bash
pip install reaper-scanner
```

Or install from source:

```bash
git clone https://github.com/iops/reaper.git
cd reaper
pip install -e ".[dev]"
```

## Quick Start

### Scan an Agent Deployment

```bash
# Auto-detect framework, JSON output
reaper scan /path/to/agent

# Force a specific framework adapter
reaper scan /path/to/agent --framework mcp_generic

# SARIF output (for GitHub Code Scanning, VS Code, etc.)
reaper scan /path/to/agent --output sarif --out-file results.sarif
```

### Probe a Live MCP Server

```bash
# Probe a stdio-based MCP server
reaper probe "node my-server.js" --transport stdio

# Probe with a human-readable name
reaper probe "python -m my_mcp_server" --transport stdio --server-name my-tools
```

### List Available Checks

```bash
reaper list-checks
```

```
ID                   Tier       Severity   Name
------------------------------------------------------------------------
RPR-CONF-001         community  high       MCP Server Missing Authentication
RPR-CONF-002         community  high       MCP Tool Permission Declaration Gaps
RPR-CONF-003         community  critical   MCP Server Auth and Authorization Config Gaps
RPR-CONF-005         community  high       MCP Scope Boundary and Isolation Failures
RPR-CONF-006         community  high       Logging, Monitoring, and HITL Gate Config Gaps
RPR-CONF-008         community  high       Cross-tool Privilege Escalation Risk Patterns
RPR-INFRA-001        community  critical   MCP Server Authentication Bypass
```

## Supported Frameworks

| Framework | Adapter | Status |
|-----------|---------|--------|
| Generic MCP | `mcp_generic` | Supported |
| OpenClaw | `openclaw` | Supported |
| Claude Code | — | Planned |
| LangChain | — | Planned |
| CrewAI | — | Planned |
| AutoGen | — | Planned |

Use `--framework auto` (default) to let REAPER detect the framework from config files.

## Output Formats

**JSON** (default) — Structured findings with evidence, remediation steps, and taxonomy mappings:

```json
{
  "check_id": "RPR-CONF-001",
  "severity": "high",
  "confidence": "high",
  "evidence": {
    "observable": "auth key absent from MCP server 'my-tools' config",
    "raw_value": "servers.my-tools: no 'auth' key present"
  },
  "remediation": {
    "description": "Configure authentication for the MCP server.",
    "steps": {"mcp_generic": "Add auth config: {\"type\": \"bearer\", \"token\": \"...\"}"},
    "effort": "trivial"
  }
}
```

**SARIF v2.1.0** — For IDE integration, GitHub Code Scanning, and CI/CD pipelines.

## API & Web UI

REAPER includes a FastAPI backend and Next.js frontend for browser-based scanning.

```bash
docker compose up
```

- API: `http://localhost:8000/api/docs`
- Web UI: `http://localhost:3000`

See the [Scanning Guide](docs/scanning-guide.md) for API usage and web UI walkthrough.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                     CLI / API                        │
├──────────────────────────────────────────────────────┤
│                  Scanner Engine                      │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐ │
│  │  Wedge 1    │  │  Wedge 2    │  │  Wedge 3     │ │
│  │  Config     │  │  Infra      │  │  Runtime     │ │
│  │  Scanner    │  │  Prober     │  │  Analyzer    │ │
│  │  (static)   │  │  (active)   │  │  (planned)   │ │
│  └─────────────┘  └─────────────┘  └──────────────┘ │
├──────────────────────────────────────────────────────┤
│  Framework Adapters    │   MCP Transport Layer       │
│  (openclaw, mcp_gen)   │   (stdio, sse planned)      │
├──────────────────────────────────────────────────────┤
│  Check Library (7 production, 4 staged)              │
│  Report Generators (JSON, SARIF)                     │
└──────────────────────────────────────────────────────┘
```

**Wedge 1** checks use `detect(TargetConfig) -> Finding | None` — pure functions, no side effects.

**Wedge 2** checks use `probe(ProbeTarget, SessionContext) -> Finding | None` — active probing via MCP transport.

**Wedge 3** (planned) will test agent behavior at runtime — prompt injection, tool misuse, output manipulation.

## Check Taxonomy

Every check maps to established security frameworks:

| OWASP ASI | Checks | Description |
|-----------|--------|-------------|
| ASI03 | RPR-CONF-002, 003, 008 | Identity and Privilege Abuse |
| ASI04 | RPR-CONF-001, RPR-INFRA-001 | Supply Chain and Component Security |
| ASI07 | RPR-CONF-005 | Insecure Inter-Agent Communication |
| ASI10 | RPR-CONF-006 | Rogue Agents / Missing Oversight |

Secondary mappings include CWE-269, CWE-284, CWE-287, CWE-306, CWE-522, CWE-668, CWE-778, CWE-862.

## Writing Custom Checks

Checks are Python modules that inherit from `ReaperCheck`:

```python
from reaper.sdk import ReaperCheck, TargetConfig, Finding

class MyCheck(ReaperCheck):
    check_id = "RPR-CUST-001"
    name = "My Custom Check"
    category = "config"
    wedge = 1
    frameworks = ["mcp_generic"]
    # ... taxonomy, severity, etc.

    def detect(self, target: TargetConfig) -> Finding | None:
        for server in target.mcp_servers:
            if some_condition(server):
                return Finding(...)
        return None
```

See the [Check Contract](docs/check-contract.md) for the full specification.

## Development

```bash
git clone https://github.com/iops/reaper.git
cd reaper
pip install -e ".[dev]"

# Run tests
pytest tests/ -x -v

# Lint
ruff check .
```

## Documentation

- [Scanning Guide](docs/scanning-guide.md) — CLI, API, and Web UI usage

## License

MIT
