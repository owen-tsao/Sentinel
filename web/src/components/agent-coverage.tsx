"use client";

import type {
  AgentConnectionResponse,
  FamilyCoverageResponse,
  IntegrationStatusResponse,
} from "@/lib/control-types";

/**
 * Rows for the "Agent coverage" settings group. The enclosing section and
 * heading come from the settings page so there is exactly one region named
 * "Agent coverage".
 */
export function AgentCoverage({
  integration,
}: {
  integration: IntegrationStatusResponse | null;
}) {
  if (!integration) {
    return (
      <p className="px-5 py-5 text-[13px] text-[var(--subtext)]">
        No mandatory agent path is running in this Sentinel process. Agent actions are
        advisory only.
      </p>
    );
  }
  return (
    <>
      <StatusRow
        label="Cursor MCP connection"
        detail={connectionDetail(integration.agent)}
        value={connectionValue(integration.agent.status)}
      />
      <StatusRow
        label="Sentinel gateway"
        detail={integration.gateway.detail}
        value={integration.gateway.status === "ready" ? "Ready" : "Unavailable"}
      />
      <StatusRow
        label="Fail-closed hooks"
        detail={integration.hooks.detail}
        value={integration.hooks.status === "ready" ? "Installed" : "Not detected"}
      />
      <StatusRow
        label="Cursor sandbox"
        detail={integration.sandbox.detail}
        value="Not verifiable"
      />
      <p className="px-5 pb-1 pt-3 text-[11px] font-medium uppercase tracking-[0.08em] text-[var(--faint)]">
        By action family · nothing here is summarised as “protected”
      </p>
      {integration.coverage.map((entry) => (
        <div
          key={entry.family}
          className="flex min-h-[52px] items-start justify-between gap-6 px-5 py-3"
        >
          <div className="min-w-0">
            <p className="text-[13px] font-medium">{familyLabel(entry.family)}</p>
            <p className="mt-0.5 text-[12px] leading-4 text-[var(--subtext)]">{entry.basis}</p>
            {entry.known_bypasses?.length ? (
              <p className="mt-0.5 text-[12px] leading-4 text-[var(--faint)]">
                Known limit: {entry.known_bypasses.join("; ")}
              </p>
            ) : null}
          </div>
          <CoverageBadge status={entry.status} />
        </div>
      ))}
    </>
  );
}

function StatusRow({
  label,
  detail,
  value,
}: {
  label: string;
  detail: string;
  value: string;
}) {
  return (
    <div className="flex min-h-[56px] items-center justify-between gap-6 px-5 py-3">
      <div className="min-w-0">
        <p className="text-[13px] font-medium">{label}</p>
        <p className="mt-0.5 text-[12px] text-[var(--subtext)]">{detail}</p>
      </div>
      <span className="shrink-0 text-[12px] text-[var(--subtext)]">{value}</span>
    </div>
  );
}

function connectionValue(status: AgentConnectionResponse["status"]) {
  return {
    connected: "Connected",
    disconnected: "Disconnected",
    never_connected: "Waiting",
  }[status];
}

function connectionDetail(agent: AgentConnectionResponse) {
  if (agent.status === "never_connected") {
    return "The Sentinel MCP shim has not called yet";
  }
  const last = agent.last_tool
    ? `Last: ${agent.last_tool} · ${agent.last_verdict ?? "no verdict"}`
    : "No tool calls yet";
  return `${last} · ${agent.mediated_calls} mediated, ${agent.rejected_calls} rejected`;
}

function familyLabel(family: string) {
  return (
    {
      sentinel_issue_fixture: "Fixture issue tools (MCP)",
      shell: "Shell commands",
      file_edit: "File edits",
      prompt: "Prompts",
      other_mcp_servers: "Other MCP servers",
      browser: "Browser",
      network: "Network",
      subagents: "Subagents",
    }[family] ?? family.replaceAll("_", " ")
  );
}

function CoverageBadge({ status }: { status: FamilyCoverageResponse["status"] }) {
  const label = {
    mandatory: "Mandatory",
    advisory: "Advisory",
    unsupported: "Unsupported",
    unavailable: "Unavailable",
  }[status];
  const tone = {
    mandatory: "border-black text-[var(--ink)]",
    advisory: "border-[var(--line)] text-[var(--subtext)]",
    unsupported: "border-[var(--line)] text-[var(--faint)]",
    unavailable: "border-[var(--line)] text-[var(--faint)] line-through",
  }[status];
  return (
    <span
      className={`mt-0.5 shrink-0 rounded-[5px] border-[1.5px] px-1.5 font-mono text-[10px] font-medium uppercase leading-[17px] tracking-[0.06em] ${tone}`}
    >
      {label}
    </span>
  );
}
