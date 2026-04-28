# REAPER Check Library Inventory

## Production Checks

| Check ID | Name | Wedge | Severity | OWASP ASI | CWE | Frameworks |
|----------|------|-------|----------|-----------|-----|------------|
| RPR-CONF-001 | MCP Server Missing Authentication | 1 | high | ASI04 | CWE-306 | openclaw, mcp_generic |
| RPR-CONF-002 | MCP Tool Permission Declaration Gaps | 1 | high | ASI03 | CWE-269, CWE-862 | mcp_generic, openclaw, langchain, crewai |
| RPR-CONF-003 | MCP Server Auth and Authorization Config Gaps | 1 | critical | ASI03 | CWE-287, CWE-862, CWE-522 | openclaw, langchain, crewai, mcp_generic |
| RPR-CONF-005 | MCP Scope Boundary and Isolation Failures | 1 | high | ASI07 | CWE-668, CWE-284 | universal |
| RPR-CONF-006 | Logging, Monitoring, and HITL Gate Config Gaps | 1 | high | ASI10 | CWE-778, CWE-862 | universal |
| RPR-CONF-008 | Cross-tool Privilege Escalation Risk Patterns | 1 | high | ASI03 | CWE-269, CWE-862 | universal |
| RPR-INFRA-001 | MCP Server Authentication Bypass | 2 | critical | ASI04 | CWE-306 | mcp_generic, openclaw |

**Totals:** 7 production checks (6 Wedge 1, 1 Wedge 2)

## Staged Checks (Pending Review)

These checks are in `checks/staged/` and may be promotable after manual review and hardening.

| Check ID | Name | Status |
|----------|------|--------|
| RPR-CONF-004 | MCP Action Directive Field Gaps | Needs review |
| RPR-CONF-007 | MCP Config Hygiene | Needs review |
| RPR-CONF-009 | Shadow Tool Exposure | Needs review |
| RPR-CONF-010 | MCP Server Identity Risk | Needs review |

## Coverage by OWASP ASI Category

| ASI Category | Description | Checks |
|--------------|-------------|--------|
| ASI03 | Identity and Privilege Abuse | RPR-CONF-002, RPR-CONF-003, RPR-CONF-008 |
| ASI04 | Supply Chain and Component Security | RPR-CONF-001, RPR-INFRA-001 |
| ASI07 | Insecure Inter-Agent Communication | RPR-CONF-005 |
| ASI10 | Rogue Agents / Missing Oversight | RPR-CONF-006 |
| ASI01 | Agent Goal Hijacking | — (requires Wedge 3) |
| ASI02 | Tool Misuse | — (requires Wedge 3) |
| ASI05 | Unexpected Code Execution | — (requires Wedge 2/3) |
| ASI06 | Memory/Context Poisoning | — (requires Wedge 3) |
| ASI08 | Cascading Failures | — (requires Wedge 2/3) |
| ASI09 | Human-Agent Trust Exploitation | — (requires Wedge 3) |

## Coverage by Wedge

| Wedge | Description | Checks | Status |
|-------|-------------|--------|--------|
| 1 | Static Configuration Analysis | 6 production + 4 staged | Active |
| 2 | Active Infrastructure Probing | 1 production | Active |
| 3 | Runtime Behavioral Analysis | 0 | Planned |
