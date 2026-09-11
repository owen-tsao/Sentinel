"use client";

import { Bot, Search, ShieldCheck } from "lucide-react";
import { useMemo, useRef, useState } from "react";

import { AgentCoverage } from "@/components/agent-coverage";
import { GitHubIcon, LinearIcon, SlackIcon } from "@/components/brand-icons";
import { useControl } from "@/components/control-provider";
import { Input } from "@/components/ui/input";
import { Eyebrow, PageHeader, Panel, StatusDot, type StatusTone } from "@/components/ui/layout";
import type { IntegrationStatusResponse } from "@/lib/control-types";
import { cn } from "@/lib/utils";

type SettingsSection = "general" | "connections" | "approvals" | "workspace";

const sections: Array<{ id: SettingsSection; label: string }> = [
  { id: "general", label: "General" },
  { id: "connections", label: "Connections" },
  { id: "approvals", label: "Approval preferences" },
  { id: "workspace", label: "Workspace access" },
];

const providers = [
  {
    name: "GitHub",
    description: "Connect repositories and review activity.",
    keywords: "github code repository oauth",
    icon: GitHubIcon,
  },
  {
    name: "Slack",
    description: "Review communication actions before they are sent.",
    keywords: "slack messages communication oauth",
    icon: SlackIcon,
  },
  {
    name: "Linear",
    description: "Supervise issue and project updates.",
    keywords: "linear issues project management oauth",
    icon: LinearIcon,
  },
];

/**
 * Settings: grouped sections. A section nav on the left; each group on the
 * right is title → one line → rows inside one white panel. Nothing here is
 * loud: there is no primary action on a settings page.
 */
export default function SettingsPage() {
  const { status } = useControl();
  const [section, setSection] = useState<SettingsSection>("connections");
  const [query, setQuery] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);
  const filteredProviders = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return providers;
    return providers.filter((provider) =>
      `${provider.name} ${provider.keywords}`.toLowerCase().includes(normalized),
    );
  }, [query]);

  return (
    <div>
      <PageHeader eyebrow="Settings" title={status?.workspace.name ?? "Your workspace"} />

      <div className="grid gap-7 lg:grid-cols-[180px_minmax(0,1fr)]">
        <nav
          aria-label="Settings sections"
          className="flex gap-1 overflow-x-auto lg:flex-col"
        >
          {sections.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-current={section === item.id ? "page" : undefined}
              className={cn(
                "h-8 shrink-0 rounded-[7px] border-[1.5px] border-transparent px-2.5 text-left text-[13px] font-medium text-[var(--subtext)] outline-none transition-colors hover:bg-[var(--hover)] hover:text-[var(--ink)] focus-visible:ring-2 focus-visible:ring-black",
                section === item.id && "border-[var(--outline)] bg-white text-[var(--ink)]",
              )}
              onClick={() => setSection(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="flex min-w-0 flex-col gap-8">
          {section === "connections" ? (
            <ConnectionsSection
              query={query}
              setQuery={setQuery}
              searchRef={searchRef}
              providers={filteredProviders}
              integration={status?.integration ?? null}
            />
          ) : null}
          {section === "general" ? <GeneralSection /> : null}
          {section === "approvals" ? <ApprovalsSection /> : null}
          {section === "workspace" ? (
            <WorkspaceSection
              name={status?.workspace.name ?? "Unavailable"}
              demoMode={Boolean(status?.runtime.demo_mode)}
            />
          ) : null}
        </div>
      </div>
    </div>
  );
}

function ConnectionsSection({
  query,
  setQuery,
  searchRef,
  providers: visibleProviders,
  integration,
}: {
  query: string;
  setQuery: (value: string) => void;
  searchRef: React.RefObject<HTMLInputElement | null>;
  providers: typeof providers;
  integration: IntegrationStatusResponse | null;
}) {
  const agentConnected = integration?.agent.status === "connected";
  const searching = Boolean(query.trim());
  return (
    <>
      <SettingsGroup
        title="Connections"
        description="The tools and agents Sentinel supervises. Connecting an account never grants an agent task authority."
        aside={
          <div className="relative w-full max-w-[260px]">
            <Search
              aria-hidden="true"
              size={14}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--faint)]"
            />
            <label htmlFor="connection-search" className="sr-only">
              Search connections
            </label>
            <Input
              ref={searchRef}
              id="connection-search"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search connections"
              className="h-8 pl-8 text-[12px]"
            />
          </div>
        }
      >
        {!searching ? (
          <>
            <GroupLabel>Connected</GroupLabel>
            <ConnectionRow
              icon={<ShieldCheck aria-hidden="true" size={16} strokeWidth={1.6} />}
              name="Local control channel"
              description="Protects this browser and workspace."
              tone="ok"
              status="Connected"
            />
            <ConnectionRow
              icon={<Bot aria-hidden="true" size={16} strokeWidth={1.6} />}
              name="Cursor (MCP)"
              description={
                integration
                  ? agentConnected
                    ? "Fixture issue tools are mediated by Sentinel; other actions stay advisory."
                    : "Sentinel is ready for the MCP shim; it has not connected yet."
                  : "External agent integrations remain advisory."
              }
              tone={integration ? (agentConnected ? "ok" : "warn") : "muted"}
              status={integration ? (agentConnected ? "Connected" : "Waiting") : "Optional"}
            />
          </>
        ) : null}

        <GroupLabel>Available · OAuth planned</GroupLabel>
        {visibleProviders.length ? (
          visibleProviders.map((provider) => (
            <ConnectionRow
              key={provider.name}
              icon={<provider.icon className="size-4" />}
              name={provider.name}
              description={provider.description}
              tone="muted"
              status="Not connected"
            />
          ))
        ) : (
          <p className="px-5 py-6 text-[13px] text-[var(--subtext)]">
            No connections match your search.
          </p>
        )}
      </SettingsGroup>

      {!searching ? (
        <SettingsGroup
          title="Agent coverage"
          description="What Sentinel can actually enforce, by action family."
          labelledBy="agent-coverage-heading"
        >
          <AgentCoverage integration={integration} />
        </SettingsGroup>
      ) : null}
    </>
  );
}

function GeneralSection() {
  return (
    <SettingsGroup
      title="General"
      description="The defaults used across this local control center."
    >
      <SettingRow label="Interface" description="Plain-language supervision" value="On" />
      <SettingRow
        label="Learning model"
        description="Decisions use deterministic rules in this build"
        value="Off"
      />
      <SettingRow
        label="Data location"
        description="Control state remains on this machine"
        value="Local"
      />
    </SettingsGroup>
  );
}

function ApprovalsSection() {
  return (
    <SettingsGroup
      title="Approval preferences"
      description="How Sentinel asks before important actions."
    >
      <SettingRow
        label="File changes"
        description="Review important create, edit, and delete actions"
        value="Always ask"
      />
      <SettingRow
        label="External communication"
        description="Review messages before they are sent"
        value="Always ask"
      />
      <SettingRow
        label="One-use decisions"
        description="Every approval applies to one unchanged attempt"
        value="Required"
      />
    </SettingsGroup>
  );
}

function WorkspaceSection({ name, demoMode }: { name: string; demoMode: boolean }) {
  return (
    <SettingsGroup
      title="Workspace access"
      description="Where the current Sentinel process is allowed to operate."
    >
      <SettingRow label="Current workspace" description={name} value="Selected" />
      <SettingRow
        label="Workspace switching"
        description="Restart Sentinel to review a different project"
        value="Locked"
      />
      <SettingRow
        label="Run mode"
        description="The current process configuration"
        value={demoMode ? "Demo" : "Local"}
      />
    </SettingsGroup>
  );
}

/** Title → one line → a white panel of rows. Optional aside (e.g. a search field) sits on the title line. */
function SettingsGroup({
  title,
  description,
  aside,
  labelledBy,
  children,
}: {
  title: string;
  description: string;
  aside?: React.ReactNode;
  labelledBy?: string;
  children: React.ReactNode;
}) {
  const headingId = labelledBy ?? `${title.toLowerCase().replaceAll(/\s+/g, "-")}-heading`;
  return (
    <section aria-labelledby={headingId}>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 id={headingId} className="text-[14px] font-semibold tracking-[-0.01em]">
            {title}
          </h2>
          <p className="mt-0.5 text-[12px] text-[var(--subtext)]">{description}</p>
        </div>
        {aside}
      </div>
      <Panel className="mt-3 divide-y divide-[var(--line)]">{children}</Panel>
    </section>
  );
}

function GroupLabel({ children }: { children: React.ReactNode }) {
  return <Eyebrow className="px-5 pb-1 pt-3">{children}</Eyebrow>;
}

function SettingRow({
  label,
  description,
  value,
}: {
  label: string;
  description: string;
  value: string;
}) {
  return (
    <div className="flex min-h-[56px] items-center justify-between gap-6 px-5 py-3">
      <div>
        <p className="text-[13px] font-medium">{label}</p>
        <p className="mt-0.5 text-[12px] text-[var(--subtext)]">{description}</p>
      </div>
      <span className="shrink-0 text-[12px] text-[var(--subtext)]">{value}</span>
    </div>
  );
}

function ConnectionRow({
  icon,
  name,
  description,
  tone,
  status,
}: {
  icon: React.ReactNode;
  name: string;
  description: string;
  tone: StatusTone;
  status: string;
}) {
  return (
    <div className="grid min-h-[56px] grid-cols-[16px_minmax(0,1fr)_auto] items-center gap-3.5 px-5 py-3">
      <span className="text-[var(--ink)]">{icon}</span>
      <div className="min-w-0">
        <p className="text-[13px] font-medium">{name}</p>
        <p className="mt-0.5 text-[12px] text-[var(--subtext)]">{description}</p>
      </div>
      <StatusDot tone={tone} className="text-[12px] text-[var(--subtext)]">
        {status}
      </StatusDot>
    </div>
  );
}
