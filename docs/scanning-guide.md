# Scanning Guide

## What REAPER Scans

REAPER inspects AI agent deployments for security vulnerabilities across two scanning modes:

**Wedge 1 — Static Configuration Analysis** examines agent config files, tool permissions, MCP server declarations, and system prompts without needing a running agent. What it looks for:
- MCP servers configured without authentication
- Tools with overly broad permission scopes (wildcard access)
- Missing input validation on tool parameters
- Destructive operations without confirmation gates
- Scope boundary and isolation failures
- Missing logging, monitoring, or human-in-the-loop gates
- Cross-tool privilege escalation patterns

**Wedge 2 — Active Infrastructure Probing** connects to live MCP server endpoints and verifies that security controls are actually enforced at runtime. What it tests:
- Whether MCP servers accept unauthenticated connections
- Whether invalid credentials are rejected
- Whether tools can be invoked without authentication

Wedge 1 tells you "your config is missing auth." Wedge 2 tells you "your server is actually accepting requests without auth right now."

## Quick Start (CLI)

### Wedge 1: Scan Agent Configs

Scan a local agent deployment:

```bash
reaper scan /path/to/agent/workspace
```

REAPER auto-detects the framework and runs all applicable Wedge 1 checks:

```
Loaded 7 checks
[mcp_generic] Found 1 agent(s)
  my-agent: 2 findings (4ms)
```

**Options:**

```bash
reaper scan /path --framework openclaw     # Force a specific framework adapter
reaper scan /path --output sarif           # SARIF format (for IDE integration)
reaper scan /path --out-file report.json   # Write to file instead of stdout
reaper scan /path --checks-dir ./checks    # Custom checks directory
reaper -v scan /path                       # Verbose (debug logging)
```

### Wedge 2: Probe Live MCP Servers

Probe a running MCP server endpoint to verify authentication enforcement:

```bash
reaper probe "python -m my_mcp_server" --transport stdio
```

This spawns the server process and sends a sequence of probes:
1. **Unauthenticated access** — connects with no credentials, tries `initialize` + `tools/list`
2. **Invalid token** — connects with a deliberately bad bearer token
3. **Unauthenticated tool invocation** — attempts `tools/call` without credentials

If any probe succeeds, the server has an authentication enforcement gap.

```
Loaded 7 checks (1 probe checks)
Probed my-server: 1 finding (312ms, 3 probes)
```

**Options:**

```bash
reaper probe "node server.js" --transport stdio          # Stdio transport (subprocess)
reaper probe "node server.js" --server-name my-tools     # Human-readable name
reaper probe "node server.js" --output sarif             # SARIF output
reaper probe "node server.js" --out-file probe.json      # Write to file
```

## Supported Frameworks

| Framework | Adapter | Status |
|-----------|---------|--------|
| OpenClaw | `openclaw` | Supported |
| Generic MCP | `mcp_generic` | Supported |
| Claude Code | `claude_code` | Planned |
| LangChain | `langchain` | Planned |
| CrewAI | `crewai` | Planned |
| AutoGen | `autogen` | Planned |
| Hermes | `hermes` | Planned |

Use `--framework auto` (default) to let REAPER detect the framework, or specify one explicitly.

## Reading Scan Output

### JSON Format (default)

The JSON report has three sections:

**Summary** — Totals at a glance:
```json
{
  "targets_scanned": 1,
  "total_findings": 1,
  "severity_counts": {"high": 1},
  "total_checks_executed": 2,
  "total_checks_skipped": 0,
  "total_errors": 0
}
```

**Findings** — Each detected vulnerability:
```json
{
  "check_id": "RPR-CONF-001",
  "severity": "high",
  "confidence": "high",
  "evidence": {
    "observable": "auth key absent from MCP server 'my-tools' config",
    "file_path": "~/.openclaw/config.json",
    "raw_value": "servers.my-tools: no 'auth' key present",
    "context": {"mcp_server": "my-tools"}
  },
  "remediation": {
    "description": "Configure authentication for the MCP server...",
    "steps": {
      "openclaw": "In ~/.openclaw/config.json, under servers...",
      "mcp_generic": "Configure your MCP server transport with..."
    },
    "references": ["https://owasp.org/..."],
    "effort": "trivial"
  },
  "taxonomy": {
    "primary": {
      "framework": "owasp_asi",
      "entry_id": "ASI04",
      "justification": "Detects unsigned, unauthenticated MCP server..."
    },
    "secondary": [...]
  }
}
```

**Key fields to look at:**

| Field | What it tells you |
|-------|-------------------|
| `severity` | How critical: `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | How certain: `high`, `medium`, `low`. Deterministic checks always report `high`. |
| `evidence.observable` | The specific thing that triggered the detection |
| `evidence.raw_value` | The actual config value that's the problem |
| `remediation.steps` | Copy-pasteable fix instructions, per framework |
| `remediation.effort` | How long the fix takes: `trivial` (<5 min), `low` (<1 hr), `medium` (<1 day), `high` (>1 day) |
| `taxonomy.primary` | OWASP ASI category this maps to |

### SARIF Format

Use `--output sarif` for IDE integration. SARIF v2.1.0 output works with VS Code, GitHub Code Scanning, and other tools that consume SARIF.

```bash
reaper scan /path --output sarif --out-file results.sarif
```

## Using the API

Start the API server:

```bash
docker compose up
# or
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### Create a Scan

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Agent Scan",
    "agent_identity": {
      "autonomy_level": 4,
      "framework": "mcp_generic"
    },
    "target": {
      "framework": "mcp_generic",
      "mcp_servers": [
        {"name": "my-server", "command": "node", "args": ["server.js"]}
      ]
    }
  }'
```

The API runs the scanner engine and returns findings immediately.

### Get Scan Results

```bash
curl http://localhost:8000/api/scans/{scan_id}
```

### Get Findings

```bash
curl http://localhost:8000/api/scans/{scan_id}/findings
```

### List All Scans

```bash
curl http://localhost:8000/api/scans
```

## Using the Web UI

Start the full stack:

```bash
docker compose up
```

Open `http://localhost:3000` in your browser.

**New Scan** — The scan wizard walks you through 5 steps:
1. Agent identity (name, autonomy level, framework)
2. Tool inventory (tool count, dangerous tool access)
3. Data exposure (PII handling, external data sources)
4. Guardrails (output filtering, human-in-the-loop)
5. Scan target (paste MCP config JSON or add servers manually)

**Results** — After submitting, the results page shows:
- Risk scores (composite, prompt risk, tool risk, output risk)
- Findings with severity badges
- Expandable cards with evidence details and remediation steps
- Taxonomy mappings (OWASP ASI, MITRE ATLAS, CWE)

**History** — Browse past scans, click to view results. Scans are persisted in SQLite and survive restarts.

## Severity Levels

| Level | Meaning | CVSS Range |
|-------|---------|------------|
| Critical | Exploitable with no interaction, full agent compromise | 9.0-10.0 |
| High | Minimal preconditions, significant unauthorized access | 7.0-8.9 |
| Medium | Specific conditions required, limited access | 4.0-6.9 |
| Low | Minor weakness, limited exploitability | 0.1-3.9 |
| Info | Security-relevant observation, not a vulnerability | N/A |

Severities are assessed against worst-case deployment — an autonomous agent with full tool access and persistence. A finding rated "high" might be less urgent in your specific deployment, but REAPER defaults to the most cautious assessment.

## Check Library

List all loaded checks:

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

Checks with the `RPR-CONF-*` prefix are Wedge 1 (static config analysis). Checks with `RPR-INFRA-*` are Wedge 2 (active infrastructure probing).

Validate a specific check module:

```bash
reaper validate-check checks/rpr_conf_001_mcp_auth.py
```

New checks can be added by placing modules in the `checks/` directory. See the check authoring section in the README for the contract.
