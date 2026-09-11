"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { useControl } from "@/components/control-provider";
import { ProposedTaskCard } from "@/components/proposed-task-card";
import { Button } from "@/components/ui/button";
import {
  COLUMN_HEAD_CLASS,
  PageHeader,
  Panel,
  SectionHeader,
  SectionLink,
  StatusDot,
  type StatusTone,
} from "@/components/ui/layout";
import { Chip, Ticket, TicketFacts, TicketFoot, TicketHead, TicketSeal } from "@/components/ui/ticket";
import { eventLabel, eventTool, verdictLabel } from "@/lib/audit-labels";
import { getAuditEvents } from "@/lib/control-api";
import type { AuditEvent, ContractRecord, ControlStatusResponse } from "@/lib/control-types";

const LEDGER_LIMIT = 12;
// Bookkeeping pre-events that always pair with a completing event; Activity shows them.
const LEDGER_HIDDEN_EVENTS = new Set(["authority_transition_prepared", "pre_decision"]);

/**
 * Overview: two columns. The left column (ticket + enforcement) sets the row
 * height; the decisions log on the right fills exactly that height and
 * scrolls inside, so both columns always end on the same line.
 */
export default function Home() {
  const { status, activeContract, approvalCount, proposal } = useControl();
  const events = useRecentEvents(activeContract?.task_id ?? null, approvalCount);

  return (
    <div className="grid gap-7 lg:min-h-[calc(100vh-52px-40px)] lg:grid-cols-[minmax(0,2.1fr)_minmax(260px,1fr)]">
      <div className="flex min-w-0 flex-col">
        <PageHeader eyebrow="Overview" title={status?.workspace.name ?? "Your workspace"} />

        {proposal ? (
          <ProposedTaskCard proposal={proposal} />
        ) : (
          <TaskTicket active={activeContract} approvalCount={approvalCount} />
        )}

        <SectionHeader
          label="Enforcement"
          className="mb-2 mt-[18px]"
          trailing={<SectionLink href="/settings">Settings →</SectionLink>}
        />
        <Panel>
          <ul className="grid grid-cols-1 sm:grid-cols-2">
            {healthItems(status).map((item, index) => (
              <li
                key={item.label}
                title={item.detail}
                className={[
                  "px-5 py-3.5",
                  index % 2 === 1 ? "sm:border-l sm:border-[var(--line)]" : "",
                  index >= 2 ? "border-t border-[var(--line)]" : "",
                  index === 1 ? "border-t border-[var(--line)] sm:border-t-0" : "",
                ].join(" ")}
              >
                <p className="text-[12px] text-[var(--subtext)]">{item.label}</p>
                <StatusDot tone={item.tone} className="mt-0.5 font-medium">
                  {item.state}
                </StatusDot>
                {item.detail ? (
                  <p className="mt-0.5 truncate font-mono text-[11px] text-[var(--faint)]">
                    {item.detail}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <div className="relative min-w-0">
        <SectionHeader
          id="ledger-heading"
          label="Recent decisions"
          className={COLUMN_HEAD_CLASS}
          trailing={<SectionLink href="/audit">Open activity →</SectionLink>}
        />
        <Panel
          aria-labelledby="ledger-heading"
          role="region"
          className="max-h-[480px] overflow-auto py-1 lg:absolute lg:inset-x-0 lg:bottom-0 lg:top-[34px] lg:max-h-none"
        >
          <Ledger events={events} />
        </Panel>
      </div>
    </div>
  );
}

function TaskTicket({
  active,
  approvalCount,
}: {
  active: ContractRecord | null;
  approvalCount: number;
}) {
  const contract = active?.contract;
  if (!active || !contract) {
    return (
      <Ticket tone="idle" className="flex-1" aria-labelledby="task-heading">
        <div className="flex items-start justify-between gap-6">
          <p className="text-[10px] font-semibold uppercase tracking-[0.12em] opacity-80">
            Sentinel authorization · Current task
          </p>
          <TicketSeal state="Idle" mark="dot" />
        </div>
        <div className="flex flex-1 flex-col items-center justify-center py-8 text-center">
          <h2
            id="task-heading"
            className="text-[24px] font-semibold leading-[1.2] tracking-[-0.03em]"
          >
            No task is active
          </h2>
          <p className="mt-2 max-w-[44ch] text-[13px] leading-5 text-[var(--subtext)]">
            Sentinel-guarded tools stay blocked until you activate a task. Your agent can
            propose one from Cursor, or you can write one here.
          </p>
          <Button asChild variant="raised" className="mt-6">
            <Link href="/tasks">Create a task</Link>
          </Button>
        </div>
      </Ticket>
    );
  }

  return (
    <Ticket className="flex-1" aria-labelledby="task-heading">
      <TicketHead
        eyebrow="Sentinel authorization · Current task"
        title={contract.objective}
        titleId="task-heading"
        meta={`Activated ${formatClock(active.created_at)} · Approval mode is on.`}
        seal={<TicketSeal state="Active" />}
      />
      <TicketFacts
        items={[
          { label: "Allowed", value: contract.allowed_operations.join(", ") },
          { label: "Environment", value: contract.environment },
          {
            label: "Targets",
            value: contract.exact_targets.length ? (
              <span className="flex flex-wrap gap-y-1">
                {contract.exact_targets.map((target) => (
                  <Chip key={target}>{target}</Chip>
                ))}
              </span>
            ) : (
              contract.maximum_scope
            ),
          },
          {
            label: "Expires",
            value: (
              <span className="font-mono text-[12px] font-medium" title={new Date(contract.expires_at).toLocaleString()}>
                {formatExpiry(contract.expires_at)} · {formatClock(contract.expires_at)}
              </span>
            ),
          },
        ]}
      />
      <TicketFoot
        note={
          approvalCount > 0 ? (
            <>
              <b className="font-semibold">
                {approvalCount === 1
                  ? "One write is waiting for you."
                  : `${approvalCount} writes are waiting for you.`}
              </b>{" "}
              Reads run freely; each write pauses for approval.
            </>
          ) : (
            "Reads run freely; each write pauses for your approval."
          )
        }
        actions={
          <>
            <Button asChild variant="quiet">
              <Link href="/tasks">Create replacement task</Link>
            </Button>
            {approvalCount > 0 ? (
              <Button asChild variant="raised">
                <Link href="/approvals">Review change</Link>
              </Button>
            ) : null}
          </>
        }
      />
    </Ticket>
  );
}

function useRecentEvents(taskId: string | null, approvalCount: number) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  useEffect(() => {
    let cancelled = false;
    getAuditEvents({ limit: 40 })
      .then((response) => {
        if (cancelled) return;
        const sorted = [...response.events].sort(
          (a, b) => (b.sequence_id ?? 0) - (a.sequence_id ?? 0),
        );
        // One row per attempt: keep the latest event for each request so a
        // single tool call reads as one line; Activity shows the full breakdown.
        const seen = new Set<string>();
        const collapsed = sorted.filter((event) => {
          if (LEDGER_HIDDEN_EVENTS.has(event.event_type)) return false;
          const key = event.request_id ?? event.event_id ?? String(event.sequence_id);
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
        setEvents(collapsed.slice(0, LEDGER_LIMIT));
      })
      .catch(() => {
        if (!cancelled) setEvents([]);
      });
    return () => {
      cancelled = true;
    };
    // Re-fetch when the task or approval queue changes; both mean new rows.
  }, [taskId, approvalCount]);
  return events;
}

function Ledger({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) {
    return (
      <p className="px-4 py-6 text-[13px] text-[var(--subtext)]">
        No decisions yet. The first mediated tool call will appear here.
      </p>
    );
  }
  return (
    <ol className="divide-y divide-[var(--line-strong)]">
      {events.map((event) => {
        const tool = eventTool(event);
        return (
          <li
            key={event.event_id ?? String(event.sequence_id)}
            className="grid grid-cols-[14px_minmax(0,1fr)] gap-x-2.5 px-4 py-2.5"
          >
            <span
              aria-hidden="true"
              className={`mt-[6px] size-1.5 rounded-full ${toneClass(event)}`}
            />
            <div className="min-w-0">
              <p className="text-[13px] font-medium">{eventLabel(event.event_type)}</p>
              {tool ? (
                <p className="mt-0.5 truncate font-mono text-[11px] text-[var(--subtext)]">
                  {tool.tool}
                  {tool.target ? ` · ${tool.target}` : ""}
                </p>
              ) : null}
              <p className="mt-1 flex justify-between gap-3 text-[11px] text-[var(--faint)]">
                <span>{event.verdict ? verdictLabel(event.verdict) : ""}</span>
                <time className="tabular font-mono">{formatTime(event.timestamp)}</time>
              </p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function toneClass(event: AuditEvent) {
  // A held proposal is the one row that is "yours to act on" without being a warning.
  if (event.event_type === "task_proposed") return "bg-[var(--main)]";
  if (!event.verdict) return "bg-[var(--muted-signal)]";
  return event.verdict === "allow"
    ? "bg-[var(--dot-ok)]"
    : event.verdict === "block"
      ? "bg-[var(--dot-off)]"
      : "bg-[var(--dot-warn)]";
}

function formatTime(value?: string) {
  if (!value) return "—";
  return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatClock(value?: string) {
  if (!value) return "—";
  return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function formatExpiry(iso: string) {
  const minutes = Math.round((new Date(iso).getTime() - Date.now()) / 60_000);
  if (minutes <= 0) return "Expired";
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest ? `${hours} h ${rest} min` : `${hours} h`;
}

function healthItems(status: ControlStatusResponse | null) {
  const integration = status?.integration ?? null;
  const agent = integration?.agent;
  return [
    {
      label: "Cursor agent",
      tone: (agent?.status === "connected" ? "ok" : agent?.status === "disconnected" ? "warn" : "muted") as StatusTone,
      state: agent?.status === "connected" ? "Connected" : agent?.status === "disconnected" ? "Disconnected" : "Waiting",
      detail: agent?.last_tool ? agent.last_tool : "mediated through MCP",
    },
    {
      label: "Hooks",
      tone: (integration?.hooks.status === "ready" ? "ok" : "off") as StatusTone,
      state: integration?.hooks.status === "ready" ? "Active" : "Not detected",
      detail: integration?.hooks.detail,
    },
    {
      label: "Sandbox",
      tone: (integration?.sandbox.status === "ready" ? "ok" : "muted") as StatusTone,
      state: integration?.sandbox.status === "ready" ? "Detected" : "Not verifiable",
      detail: integration?.sandbox.detail,
    },
    {
      label: "Executor",
      tone: (status?.runtime.docker.status === "ready" ? "ok" : "off") as StatusTone,
      state: status?.runtime.docker.status === "ready" ? "Ready" : "Unavailable",
      detail: status?.runtime.docker.detail,
    },
  ];
}
