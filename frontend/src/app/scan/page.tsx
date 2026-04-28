"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, type ScanCreateRequest, type McpServerInput } from "@/lib/api";

const FRAMEWORKS = ["openclaw", "claude_code", "langchain", "crewai", "autogen", "mcp_generic", "hermes", "unknown"];
const AUTH_MECHANISMS = [
  { value: "none", label: "None" },
  { value: "api_key_static", label: "Static API Key" },
  { value: "service_account", label: "Service Account" },
  { value: "oauth_user", label: "OAuth (User Identity)" },
];

function Label({ children }: { children: React.ReactNode }) {
  return <label className="block text-sm font-medium mb-1.5">{children}</label>;
}

function HelpText({ children }: { children: React.ReactNode }) {
  return <p className="text-xs text-[var(--muted)] mt-1">{children}</p>;
}

function Slider({
  label,
  help,
  value,
  onChange,
  min = 0,
  max = 4,
  labels,
}: {
  label: string;
  help: string;
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
  labels?: string[];
}) {
  return (
    <div>
      <Label>
        {label}: <span className="text-[var(--accent)] font-mono">{value}</span>
        {labels && labels[value] && (
          <span className="text-[var(--muted)] font-normal ml-2">({labels[value]})</span>
        )}
      </Label>
      <input
        type="range"
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full accent-[var(--accent)]"
      />
      <HelpText>{help}</HelpText>
    </div>
  );
}

export default function ScanPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);

  const [form, setForm] = useState<ScanCreateRequest>({
    name: "",
    agent_identity: { autonomy_level: 2, model_hardening: 1, framework: "unknown", model_provider: "unknown" },
    tool_inventory: { tool_count: 5, write_capable_pct: 30, auth_mechanism: "api_key_static", mcp_servers: [] },
    data_exposure: { pii_in_context: 1, untrusted_rag_sources: 1, data_stores_accessible: [], secrets_in_prompt: false },
    guardrails: { input_filter_strength: 1, hitl_coverage_pct: 20, output_filter_strength: 1, instruction_hierarchy: false },
  });

  const [mcpServers, setMcpServers] = useState<McpServerInput[]>([]);
  const [configJson, setConfigJson] = useState("");
  const [configError, setConfigError] = useState("");

  const addMcpServer = () => {
    setMcpServers((prev) => [...prev, { name: "", auth: null }]);
  };
  const removeMcpServer = (i: number) => {
    setMcpServers((prev) => prev.filter((_, idx) => idx !== i));
  };
  const updateMcpServer = (i: number, field: string, value: unknown) => {
    setMcpServers((prev) =>
      prev.map((s, idx) => (idx === i ? { ...s, [field]: value } : s)),
    );
  };

  const update = <K extends keyof ScanCreateRequest>(section: K, field: string, value: unknown) => {
    setForm((prev) => ({
      ...prev,
      [section]: { ...prev[section] as Record<string, unknown>, [field]: value },
    }));
  };

  const handleSubmit = async () => {
    setLoading(true);
    try {
      // Build target config from MCP servers or pasted JSON
      let target = undefined;
      if (configJson.trim()) {
        try {
          const parsed = JSON.parse(configJson);
          // Accept either { mcpServers: {...} } or { servers: {...} } or raw server list
          const servers = parsed.mcpServers || parsed.servers || parsed;
          const serverList: McpServerInput[] = [];
          if (typeof servers === "object" && !Array.isArray(servers)) {
            for (const [name, cfg] of Object.entries(servers)) {
              serverList.push({ name, ...(cfg as Record<string, unknown>) } as McpServerInput);
            }
          }
          target = { framework: form.agent_identity.framework, mcp_servers: serverList };
          setConfigError("");
        } catch {
          setConfigError("Invalid JSON");
          setLoading(false);
          return;
        }
      } else if (mcpServers.length > 0) {
        target = { framework: form.agent_identity.framework, mcp_servers: mcpServers };
      }

      const result = await api.createScan({
        ...form,
        name: form.name || "Untitled Scan",
        target: target || null,
      });
      router.push(`/scan/results?id=${result.scan_id}`);
    } catch (err) {
      console.error(err);
      setLoading(false);
    }
  };

  const steps = [
    {
      title: "Agent Identity",
      content: (
        <div className="space-y-6">
          <div>
            <Label>Scan Name</Label>
            <input
              type="text"
              placeholder="My Agent Scan"
              value={form.name}
              onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
              className="w-full px-3 py-2 bg-[var(--background)] border border-[var(--card-border)] rounded-lg focus:border-[var(--accent)] outline-none"
            />
          </div>
          <Slider
            label="Autonomy Level"
            help="0 = chatbot with no tools. 4 = fully autonomous agent."
            value={form.agent_identity.autonomy_level}
            onChange={(v) => update("agent_identity", "autonomy_level", v)}
            labels={["Chatbot", "Single tool + HITL", "Chains + checkpoints", "Autonomous + logging", "Fully autonomous"]}
          />
          <Slider
            label="Model Hardening"
            help="0 = base model, no safety training. 4 = red-teamed with layered defenses."
            value={form.agent_identity.model_hardening}
            onChange={(v) => update("agent_identity", "model_hardening", v)}
            labels={["Base model", "Safety-tuned", "RLHF + filters", "Red-teamed", "Defense-in-depth"]}
          />
          <div>
            <Label>Framework</Label>
            <select
              value={form.agent_identity.framework}
              onChange={(e) => update("agent_identity", "framework", e.target.value)}
              className="w-full px-3 py-2 bg-[var(--background)] border border-[var(--card-border)] rounded-lg"
            >
              {FRAMEWORKS.map((f) => (
                <option key={f} value={f}>{f}</option>
              ))}
            </select>
          </div>
        </div>
      ),
    },
    {
      title: "Tool Inventory",
      content: (
        <div className="space-y-6">
          <Slider
            label="Tool Count"
            help="Total number of tools the agent can access."
            value={form.tool_inventory.tool_count}
            onChange={(v) => update("tool_inventory", "tool_count", v)}
            min={0}
            max={50}
          />
          <Slider
            label="Write-Capable Tools (%)"
            help="Percentage of tools that can modify external state."
            value={form.tool_inventory.write_capable_pct}
            onChange={(v) => update("tool_inventory", "write_capable_pct", v)}
            min={0}
            max={100}
          />
          <div>
            <Label>Authentication Mechanism</Label>
            <select
              value={form.tool_inventory.auth_mechanism}
              onChange={(e) => update("tool_inventory", "auth_mechanism", e.target.value)}
              className="w-full px-3 py-2 bg-[var(--background)] border border-[var(--card-border)] rounded-lg"
            >
              {AUTH_MECHANISMS.map((m) => (
                <option key={m.value} value={m.value}>{m.label}</option>
              ))}
            </select>
            <HelpText>OAuth (User Identity) is highest risk — agent actions are indistinguishable from user actions.</HelpText>
          </div>
        </div>
      ),
    },
    {
      title: "Data Exposure",
      content: (
        <div className="space-y-6">
          <Slider
            label="PII in Context"
            help="Level of personally identifiable information accessible to the agent."
            value={form.data_exposure.pii_in_context}
            onChange={(v) => update("data_exposure", "pii_in_context", v)}
            labels={["None", "Names/emails", "Phone/address", "Financial", "SSN/medical/credentials"]}
          />
          <Slider
            label="Untrusted RAG Sources"
            help="How attacker-influenceable are the agent's retrieval sources?"
            value={form.data_exposure.untrusted_rag_sources}
            onChange={(v) => update("data_exposure", "untrusted_rag_sources", v)}
            labels={["None", "Internal docs", "Curated external", "Web search", "Public wikis/forums"]}
          />
          <div className="flex items-center gap-3">
            <input
              type="checkbox"
              id="secrets"
              checked={form.data_exposure.secrets_in_prompt}
              onChange={(e) => update("data_exposure", "secrets_in_prompt", e.target.checked)}
              className="accent-[var(--accent)] w-4 h-4"
            />
            <label htmlFor="secrets" className="text-sm">Secrets in system prompt (API keys, credentials)</label>
          </div>
        </div>
      ),
    },
    {
      title: "Guardrails",
      content: (
        <div className="space-y-6">
          <Slider
            label="Input Filter Strength"
            help="How strong is the input filtering / injection detection?"
            value={form.guardrails.input_filter_strength}
            onChange={(v) => update("guardrails", "input_filter_strength", v)}
            labels={["None", "Basic regex", "Pattern matching", "ML classifier", "Defense-in-depth"]}
          />
          <Slider
            label="HITL Coverage (%)"
            help="What percentage of tool calls require human approval?"
            value={form.guardrails.hitl_coverage_pct}
            onChange={(v) => update("guardrails", "hitl_coverage_pct", v)}
            min={0}
            max={100}
          />
          <Slider
            label="Output Filter Strength"
            help="How strong is the output filtering / content moderation?"
            value={form.guardrails.output_filter_strength}
            onChange={(v) => update("guardrails", "output_filter_strength", v)}
            labels={["None", "Basic", "Moderate", "Strong", "Defense-in-depth"]}
          />
          <div className="flex items-center gap-3">
            <input
              type="checkbox"
              id="hierarchy"
              checked={form.guardrails.instruction_hierarchy}
              onChange={(e) => update("guardrails", "instruction_hierarchy", e.target.checked)}
              className="accent-[var(--accent)] w-4 h-4"
            />
            <label htmlFor="hierarchy" className="text-sm">Instruction hierarchy enforced (system &gt; user privilege separation)</label>
          </div>
        </div>
      ),
    },
    {
      title: "Scan Target",
      content: (
        <div className="space-y-6">
          <p className="text-sm text-[var(--muted)]">
            Provide your agent&apos;s MCP server configuration to run vulnerability checks.
            Either add servers individually or paste your config JSON below.
          </p>

          {/* Structured MCP server input */}
          <div>
            <Label>MCP Servers</Label>
            {mcpServers.map((server, i) => (
              <div key={i} className="flex gap-2 mb-2 items-start">
                <input
                  type="text"
                  placeholder="Server name"
                  value={server.name}
                  onChange={(e) => updateMcpServer(i, "name", e.target.value)}
                  className="flex-1 px-3 py-2 bg-[var(--background)] border border-[var(--card-border)] rounded-lg text-sm"
                />
                <select
                  aria-label={`Auth type for ${server.name || "server"}`}
                  value={server.auth ? (server.auth as Record<string, string>).type || "none" : "none"}
                  onChange={(e) => {
                    const type = e.target.value;
                    updateMcpServer(i, "auth", type === "none" ? null : { type });
                  }}
                  className="px-3 py-2 bg-[var(--background)] border border-[var(--card-border)] rounded-lg text-sm"
                >
                  <option value="none">No Auth</option>
                  <option value="bearer">Bearer Token</option>
                  <option value="oauth">OAuth</option>
                </select>
                <button
                  onClick={() => removeMcpServer(i)}
                  className="px-2 py-2 text-red-400 hover:text-red-300 text-sm"
                >
                  Remove
                </button>
              </div>
            ))}
            <button
              onClick={addMcpServer}
              className="text-sm text-[var(--accent)] hover:underline"
            >
              + Add MCP Server
            </button>
          </div>

          <div className="relative">
            <div className="absolute inset-x-0 top-1/2 border-t border-[var(--card-border)]" />
            <div className="relative flex justify-center">
              <span className="bg-[var(--card)] px-3 text-xs text-[var(--muted)]">or paste config JSON</span>
            </div>
          </div>

          {/* JSON paste */}
          <div>
            <Label>Config JSON</Label>
            <textarea
              rows={8}
              placeholder={'{\n  "mcpServers": {\n    "my-tools": {\n      "command": "npx",\n      "args": ["my-mcp-server"]\n    }\n  }\n}'}
              value={configJson}
              onChange={(e) => { setConfigJson(e.target.value); setConfigError(""); }}
              className="w-full px-3 py-2 bg-[var(--background)] border border-[var(--card-border)] rounded-lg font-mono text-sm resize-y"
            />
            {configError && <p className="text-red-400 text-xs mt-1">{configError}</p>}
            <HelpText>
              Accepts Claude Desktop format (&quot;mcpServers&quot;) or generic MCP format (&quot;servers&quot;).
            </HelpText>
          </div>
        </div>
      ),
    },
  ];

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold mb-8">New Scan</h1>

      {/* Step indicator */}
      <div className="flex gap-2 mb-8">
        {steps.map((s, i) => (
          <button
            key={i}
            onClick={() => setStep(i)}
            className={`flex-1 py-2 px-3 text-xs font-medium rounded-lg transition-colors ${
              i === step
                ? "bg-[var(--accent)] text-white"
                : i < step
                  ? "bg-[var(--accent-muted)] text-white"
                  : "bg-[var(--card)] border border-[var(--card-border)] text-[var(--muted)]"
            }`}
          >
            {s.title}
          </button>
        ))}
      </div>

      {/* Step content */}
      <div className="p-6 rounded-lg border border-[var(--card-border)] bg-[var(--card)]">
        <h2 className="text-lg font-semibold mb-4">{steps[step].title}</h2>
        {steps[step].content}
      </div>

      {/* Navigation */}
      <div className="flex justify-between mt-6">
        <button
          onClick={() => setStep((s) => Math.max(0, s - 1))}
          disabled={step === 0}
          className="px-4 py-2 border border-[var(--card-border)] rounded-lg disabled:opacity-30 hover:border-[var(--accent)] transition-colors"
        >
          Back
        </button>
        {step < steps.length - 1 ? (
          <button
            onClick={() => setStep((s) => s + 1)}
            className="px-6 py-2 bg-[var(--accent)] text-white rounded-lg hover:bg-[var(--accent-muted)] transition-colors"
          >
            Next
          </button>
        ) : (
          <button
            onClick={handleSubmit}
            disabled={loading}
            className="px-6 py-2 bg-[var(--accent)] text-white rounded-lg hover:bg-[var(--accent-muted)] transition-colors disabled:opacity-50"
          >
            {loading ? "Scanning..." : "Run Scan"}
          </button>
        )}
      </div>
    </div>
  );
}
