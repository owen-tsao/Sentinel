"use client";

import type {
  AgentConnectionResponse,
  FamilyCoverageResponse,
  IntegrationStatusResponse,
} from "@/lib/control-types";

const sectionLabelClass =
  "text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--faint)]";

export function AgentCoverage({
  integration,
}: {
  integration: IntegrationStatusResponse | null;
}) {
  return (
    <section aria-labelledby="agent-coverage-heading">
      <h2 id="agent-coverage-heading" className={sectionLabelClass}>
        Agent coverage
      </h2>
      {integration ? (
        <>
          <div className="mt-3 divide-y divide-[var(--line)]">
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
          </div>
          <p className="mt-6 text-[10px] text-[var(--faint)]">
            What Sentinel can actually enforce, by action family. Nothing here is
            summarised as “protected”.
          </p>
          <ul className="mt-2 divide-y divide-[var(--line)]">
            {integration.coverage.map((entry) => (
              <li
                key={entry.family}
                className="flex min-h-12 items-start justify-between gap-6 py-3"
              >
                <div className="min-w-0">
                  <p className="text-[12px] font-medium">{familyLabel(entry.family)}</p>
                  <p className="mt-0.5 text-[10px] leading-4 text-[var(--subtext)]">
                    {entry.basis}
                  </p>
                  {entry.known_bypasses?.length ? (
                    <p className="mt-0.5 text-[10px] leading-4 text-[var(--faint)]">
                      Known limit: {entry.known_bypasses.join("; ")}
                    </p>
                  ) : null}
                </div>
                <CoverageBadge status={entry.status} />
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p className="mt-3 text-[12px] text-[var(--subtext)]">
          No mandatory agent path is running in this Sentinel process. Agent
          actions are advisory only.
        </p>
      )}
    </section>
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
    <div className="flex min-h-14 items-center justify-between gap-6">
      <div>
        <p className="text-[12px] font-medium">{label}</p>
        <p className="mt-0.5 text-[10px] text-[var(--subtext)]">{detail}</p>
      </div>
      <span className="shrink-0 text-[11px] text-[var(--subtext)]">{value}</span>
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
    mandatory: "border-black bg-[var(--main-soft)] text-[var(--ink)]",
    advisory: "border-[var(--line)] text-[var(--subtext)]",
    unsupported: "border-[var(--line)] text-[var(--faint)]",
    unavailable: "border-[var(--line)] text-[var(--faint)] line-through",
  }[status];
  return (
    <span
      className={`shrink-0 rounded-[4px] border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.06em] ${tone}`}
    >
      {label}
    </span>
  );
}
