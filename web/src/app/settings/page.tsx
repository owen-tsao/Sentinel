"use client";

import { Bot, Search, ShieldCheck } from "lucide-react";
import { useMemo, useRef, useState } from "react";

import { GitHubIcon, LinearIcon, SlackIcon } from "@/components/brand-icons";
import { useControl } from "@/components/control-provider";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

type SettingsSection =
  | "general"
  | "connections"
  | "approvals"
  | "workspace";

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

  function focusConnections() {
    setSection("connections");
    window.requestAnimationFrame(() => searchRef.current?.focus());
  }

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#4f6fad]">
            Settings
          </p>
          <h1 className="mt-2 text-[30px] font-semibold tracking-[-0.045em]">
            Make Sentinel yours
          </h1>
          <p className="mt-2 max-w-2xl text-[13px] leading-6 text-[var(--subtext)]">
            Manage connections, workspace access, and approval preferences in
            one place.
          </p>
        </div>
        <Button onClick={focusConnections}>View planned connections</Button>
      </div>

      <div className="mt-10 grid gap-8 border-t border-[var(--line)] pt-6 lg:grid-cols-[190px_minmax(0,1fr)] lg:gap-11">
        <nav
          aria-label="Settings sections"
          className="flex overflow-x-auto border-b border-[var(--line)] pb-3 lg:flex-col lg:gap-1 lg:border-0 lg:pb-0"
        >
          {sections.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-current={section === item.id ? "page" : undefined}
              className={cn(
                "h-10 shrink-0 rounded-[5px] px-3 text-left text-[11px] text-[var(--subtext)] outline-none transition-colors hover:bg-[var(--main-faint)] hover:text-[var(--ink)] focus-visible:ring-2 focus-visible:ring-black",
                section === item.id &&
                  "bg-[var(--main-soft)] font-semibold text-[var(--ink)]",
              )}
              onClick={() => setSection(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="min-w-0">
          {section === "connections" ? (
            <ConnectionsSection
              query={query}
              setQuery={setQuery}
              searchRef={searchRef}
              providers={filteredProviders}
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
}: {
  query: string;
  setQuery: (value: string) => void;
  searchRef: React.RefObject<HTMLInputElement | null>;
  providers: typeof providers;
}) {
  return (
    <section aria-labelledby="connections-heading">
      <h2
        id="connections-heading"
        className="text-[19px] font-semibold tracking-[-0.025em]"
      >
        Connections
      </h2>
      <p className="mt-1 text-[11px] text-[var(--subtext)]">
        Connect the tools and agents you want Sentinel to supervise.
      </p>

      <div className="relative mt-6">
        <Search
          aria-hidden="true"
          size={16}
          className="pointer-events-none absolute left-3.5 top-3 text-[var(--faint)]"
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
          className="h-10 pl-10"
        />
      </div>

      {!query.trim() ? (
        <div className="mt-8">
          <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--faint)]">
            Connected
          </p>
          <ConnectionRow
            icon={ShieldCheck}
            name="Local control channel"
            description="Protects this browser and workspace."
            status="Connected"
          />
          <ConnectionRow
            icon={Bot}
            name="Coding agent"
            description="External agent integrations remain advisory."
            status="Optional"
          />
        </div>
      ) : null}

      <div className="mt-8">
        <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--faint)]">
          Available
        </p>
        {visibleProviders.length ? (
          visibleProviders.map((provider) => (
            <ProviderRow key={provider.name} {...provider} />
          ))
        ) : (
          <p className="border-t border-[var(--line)] py-8 text-[11px] text-[var(--subtext)]">
            No connections match your search.
          </p>
        )}
      </div>

      <p className="mt-8 border-t border-[var(--line)] pt-4 text-[10px] leading-5 text-[var(--subtext)]">
        OAuth connections are planned, not active in this local build.
        Connecting an account will never grant an agent task authority.
      </p>
    </section>
  );
}

function GeneralSection() {
  return (
    <SettingsGroup
      title="General"
      description="The defaults used across this local control center."
    >
      <SettingRow
        label="Interface"
        description="Plain-language supervision"
        value="On"
      />
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

function WorkspaceSection({
  name,
  demoMode,
}: {
  name: string;
  demoMode: boolean;
}) {
  return (
    <SettingsGroup
      title="Workspace access"
      description="Where the current Sentinel process is allowed to operate."
    >
      <SettingRow
        label="Current workspace"
        description={name}
        value="Selected"
      />
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

function SettingsGroup({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <h2 className="text-[19px] font-semibold tracking-[-0.025em]">{title}</h2>
      <p className="mt-1 text-[11px] text-[var(--subtext)]">{description}</p>
      <div className="mt-6">{children}</div>
    </section>
  );
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
    <div className="flex min-h-16 items-center justify-between gap-6 border-t border-[var(--line)]">
      <div>
        <p className="text-[12px] font-medium">{label}</p>
        <p className="mt-0.5 text-[10px] text-[var(--subtext)]">
          {description}
        </p>
      </div>
      <span className="shrink-0 text-[11px] text-[var(--subtext)]">{value}</span>
    </div>
  );
}

function ConnectionRow({
  icon: Icon,
  name,
  description,
  status,
}: {
  icon: typeof Bot;
  name: string;
  description: string;
  status: string;
}) {
  return (
    <div className="grid min-h-[68px] grid-cols-[42px_minmax(0,1fr)_auto] items-center gap-3.5 border-t border-[var(--line)]">
      <div className="grid size-[34px] place-items-center rounded-[5px] border border-[rgba(136,170,238,0.55)] bg-[var(--main-soft)] text-[#294d91]">
        <Icon aria-hidden="true" size={16} />
      </div>
      <div>
        <p className="text-[12px] font-medium">{name}</p>
        <p className="mt-0.5 text-[10px] text-[var(--subtext)]">
          {description}
        </p>
      </div>
      <span className="text-[10px] font-medium text-[#4f6fad]">{status}</span>
    </div>
  );
}

function ProviderRow({
  name,
  description,
  icon: Icon,
}: (typeof providers)[number]) {
  return (
    <div className="grid min-h-[68px] grid-cols-[42px_minmax(0,1fr)_auto] items-center gap-3.5 border-t border-[var(--line)]">
      <div className="grid size-[34px] place-items-center rounded-[5px] border border-[rgba(136,170,238,0.55)] bg-[var(--main-soft)] text-[#294d91]">
        <Icon className="size-4" />
      </div>
      <div>
        <p className="text-[12px] font-medium">{name}</p>
        <p className="mt-0.5 text-[10px] text-[var(--subtext)]">
          {description}
        </p>
      </div>
      <span className="text-[10px] text-[var(--subtext)]">OAuth planned</span>
    </div>
  );
}
