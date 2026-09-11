"use client";

import { CircleAlert } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  COLUMN_HEAD_CLASS,
  Eyebrow,
  KeyValueList,
  PageHeader,
  Panel,
  SectionHeader,
  StatusDot,
  type StatusTone,
} from "@/components/ui/layout";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { eventLabel, verdictLabel } from "@/lib/audit-labels";
import { ControlApiError, getAuditEvents } from "@/lib/control-api";
import type { AuditEvent } from "@/lib/control-types";
import { cn } from "@/lib/utils";

const eventTypes = [
  "authority_transition_prepared",
  "authority_transition_completed",
  "pre_decision",
  "decision",
  "exact_action_approved",
  "exact_action_denied",
  "execution_admitted",
  "post_execution",
];

/**
 * Activity: filters on one line, then master-detail. The list panel (grouped
 * by day) sets the height; the detail panel fills it and scrolls internally so
 * both columns end on the same line.
 */
export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [taskId, setTaskId] = useState("");
  const [eventType, setEventType] = useState("all");
  const [verdict, setVerdict] = useState("all");
  const [timeRange, setTimeRange] = useState("24h");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const applyEvents = useCallback((incoming: AuditEvent[]) => {
    const nextEvents = sortEvents(incoming);
    setEvents(nextEvents);
    setSelected((current) =>
      current ? nextEvents.find((event) => event.event_id === current.event_id) ?? null : null,
    );
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await getAuditEvents({
        taskId: taskId.trim() || undefined,
        eventType: eventType === "all" ? undefined : eventType,
        verdict: verdict === "all" ? undefined : verdict,
        startTime: startForRange(timeRange),
      });
      applyEvents(response.events);
    } catch (caught) {
      setError(loadErrorMessage(caught));
    } finally {
      setLoading(false);
    }
  }, [applyEvents, eventType, taskId, timeRange, verdict]);

  useEffect(() => {
    let cancelled = false;
    void getAuditEvents({ startTime: startForRange("24h") })
      .then((response) => {
        if (!cancelled) applyEvents(response.events);
      })
      .catch((caught) => {
        if (!cancelled) setError(loadErrorMessage(caught));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [applyEvents]);

  const groups = useMemo(() => groupEventsByDay(events), [events]);
  const summary = useMemo(
    () => ({
      total: events.length,
      approvals: events.filter((event) => event.event_type === "exact_action_approved").length,
      blocked: events.filter((event) => event.verdict === "block").length,
    }),
    [events],
  );

  return (
    <div className="flex flex-col lg:h-[calc(100vh-52px-40px)]">
      <PageHeader eyebrow="Activity" title="What happened" />

      {error ? (
        <Alert variant="destructive" className="mb-4">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>Activity unavailable</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <section aria-labelledby="activity-filters" className="mb-6">
        <h2 id="activity-filters" className="sr-only">
          Activity filters
        </h2>
        <div className="grid items-end gap-3 md:grid-cols-2 xl:grid-cols-[1.2fr_1fr_1fr_0.8fr_auto]">
          <Filter label="Task reference" htmlFor="audit-task">
            <Input
              id="audit-task"
              value={taskId}
              onChange={(event) => setTaskId(event.target.value)}
              placeholder="Search a task"
              className="font-mono text-[12px]"
            />
          </Filter>
          <Filter label="Show" htmlFor="audit-event-type">
            <Select value={eventType} onValueChange={setEventType}>
              <SelectTrigger id="audit-event-type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">All activity</SelectItem>
                  {eventTypes.map((value) => (
                    <SelectItem key={value} value={value}>
                      {eventLabel(value)}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
          </Filter>
          <Filter label="Decision" htmlFor="audit-verdict">
            <Select value={verdict} onValueChange={setVerdict}>
              <SelectTrigger id="audit-verdict">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">All decisions</SelectItem>
                  <SelectItem value="allow">Allowed</SelectItem>
                  <SelectItem value="warn">Warning</SelectItem>
                  <SelectItem value="confirm_required">Asked for approval</SelectItem>
                  <SelectItem value="block">Blocked</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </Filter>
          <Filter label="Time" htmlFor="audit-time">
            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger id="audit-time">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="1h">Last hour</SelectItem>
                  <SelectItem value="24h">Last 24 hours</SelectItem>
                  <SelectItem value="7d">Last 7 days</SelectItem>
                  <SelectItem value="all">All activity</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </Filter>
          {/* Applying also re-fetches, so there is no separate refresh button. */}
          <Button variant="secondary" className="h-9" onClick={load} disabled={loading}>
            Apply filters
          </Button>
        </div>
      </section>

      {/* Both panels fill the remaining height and scroll inside, so the
          detail stays beside the list however long the day gets. */}
      <div className="grid min-h-0 flex-1 gap-7 lg:grid-cols-[minmax(0,1.6fr)_minmax(280px,1fr)]">
        <div className="flex min-h-0 min-w-0 flex-col">
          <SectionHeader
            id="activity-list-heading"
            label="Events"
            className={COLUMN_HEAD_CLASS}
            trailing={
              <span className="text-[12px] text-[var(--subtext)]">
                {summary.total} shown · {summary.approvals} approved · {summary.blocked} blocked
              </span>
            }
          />
          <Panel
            role="region"
            aria-labelledby="activity-list-heading"
            className="min-h-[240px] flex-1 overflow-auto py-1 lg:min-h-0"
          >
            {!loading && events.length === 0 ? (
              <div className="grid min-h-[240px] place-items-center px-6 text-center">
                <div>
                  <p className="text-[13px] font-medium">No matching activity</p>
                  <p className="mt-1 text-[12px] text-[var(--subtext)]">
                    Try a wider time range or clear a filter.
                  </p>
                </div>
              </div>
            ) : (
              groups.map((group) => (
                <section key={group.key} aria-labelledby={`day-${group.key}`}>
                  <h2 id={`day-${group.key}`} className="px-4 pb-1 pt-3">
                    <Eyebrow>{group.label}</Eyebrow>
                  </h2>
                  <ol className="divide-y divide-[var(--line)]">
                    {group.events.map((event) => (
                      <ActivityRow
                        key={event.event_id}
                        event={event}
                        selected={selected?.event_id === event.event_id}
                        onSelect={() => setSelected(event)}
                      />
                    ))}
                  </ol>
                </section>
              ))
            )}
          </Panel>
        </div>

        <div className="flex min-h-0 min-w-0 flex-col">
          <SectionHeader id="activity-detail-heading" label="Activity details" className={COLUMN_HEAD_CLASS} />
          <Panel
            role="region"
            aria-labelledby="activity-detail-heading"
            className="min-h-[160px] flex-1 overflow-auto px-5 py-4 lg:min-h-0"
          >
            {selected ? (
              <EventDetail event={selected} />
            ) : (
              <p className="text-[13px] text-[var(--subtext)]">Choose an item to see why it happened.</p>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function ActivityRow({
  event,
  selected,
  onSelect,
}: {
  event: AuditEvent;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <li>
      <button
        type="button"
        aria-label={`View ${event.event_type} event sequence ${event.sequence_id ?? "pending"}`}
        aria-current={selected ? "true" : undefined}
        className={cn(
          "grid w-full grid-cols-[14px_minmax(0,1fr)_auto] items-start gap-x-2.5 px-4 py-2.5 text-left outline-none transition-colors hover:bg-[var(--hover)] focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-inset",
          selected && "bg-[var(--hover)]",
        )}
        onClick={onSelect}
      >
        <span aria-hidden="true" className={cn("mt-[6px] size-1.5 rounded-full", toneClass(eventTone(event)))} />
        <span className="min-w-0">
          <span className="block text-[13px] font-medium">{eventLabel(event.event_type)}</span>
          <span className="mt-0.5 block truncate text-[12px] text-[var(--subtext)]">
            {eventDescription(event)}
          </span>
        </span>
        <time className="tabular font-mono text-[11px] text-[var(--faint)]">{formatTime(event.timestamp)}</time>
      </button>
    </li>
  );
}

function EventDetail({ event }: { event: AuditEvent }) {
  return (
    <div>
      <div className="flex items-start justify-between gap-4">
        <StatusDot tone={eventTone(event)} className="text-[12px] text-[var(--subtext)]">
          {event.verdict ? verdictLabel(event.verdict) : "Recorded"}
        </StatusDot>
        {event.sequence_id ? (
          <span className="font-mono text-[11px] text-[var(--faint)]">#{event.sequence_id}</span>
        ) : null}
      </div>
      <p className="mt-2 text-[14px] font-semibold tracking-[-0.01em]">{eventLabel(event.event_type)}</p>
      <p className="mt-1 text-[12px] leading-5 text-[var(--subtext)]">{eventDescription(event)}</p>
      <KeyValueList
        className="mt-4 border-t border-[var(--line)] pt-4 text-[12px]"
        labelWidth="96px"
        items={[
          { label: "When", value: formatTimestamp(event.timestamp) },
          { label: "Decision", value: event.verdict ? verdictLabel(event.verdict) : "Recorded" },
          { label: "Environment", value: event.environment ? titleCase(event.environment) : "Current workspace" },
          ...(typeof event.details?.tool === "string"
            ? [{ label: "Tool", value: <code className="font-mono text-[11px] font-normal">{event.details.tool}</code> }]
            : []),
        ]}
      />
      {event.reason_codes?.length ? (
        <div className="mt-4 border-t border-[var(--line)] pt-4">
          <Eyebrow>Why</Eyebrow>
          <ul className="mt-2 flex flex-col gap-1.5">
            {event.reason_codes.map((reason) => (
              <li key={reason} className="text-[12px] leading-5">
                {friendlyReason(reason)}
                <span className="block font-mono text-[10px] leading-4 text-[var(--faint)]">{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function Filter({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={htmlFor} className="text-[12px] font-medium">
        {label}
      </label>
      {children}
    </div>
  );
}

function eventTone(event: AuditEvent): StatusTone {
  if (event.event_type === "task_proposed") return "main";
  if (event.event_type === "exact_action_denied") return "off";
  if (!event.verdict) return "muted";
  return event.verdict === "allow" ? "ok" : event.verdict === "block" ? "off" : "warn";
}

function toneClass(tone: StatusTone) {
  return {
    ok: "bg-[var(--dot-ok)]",
    warn: "bg-[var(--dot-warn)]",
    off: "bg-[var(--dot-off)]",
    muted: "bg-[var(--muted-signal)]",
    main: "bg-[var(--main)]",
  }[tone];
}

function loadErrorMessage(caught: unknown) {
  return caught instanceof ControlApiError && caught.status === 401
    ? "Your control session expired. Open a fresh pairing link."
    : "Activity could not be loaded.";
}
function eventDescription(event: AuditEvent) {
  const tool = mcpToolSummary(event);
  if (event.event_type === "exact_action_denied") return "Nothing was changed.";
  if (event.event_type === "exact_action_approved") {
    return "The approval can be used once.";
  }
  if (event.event_type.startsWith("task_propos")) {
    return proposalDescription(event);
  }
  if (event.event_type === "post_execution") {
    if (tool) {
      return event.verdict === "allow"
        ? `${tool} finished through Sentinel.`
        : `${tool} did not complete; nothing was written.`;
    }
    const exitCode = event.details?.exit_code;
    return exitCode === 0
      ? "The approved change finished successfully."
      : "The approved change finished with an issue.";
  }
  if (event.event_type === "execution_admitted") {
    return tool
      ? `Sentinel admitted ${tool}.`
      : "Sentinel allowed the approved attempt to begin.";
  }
  if (event.event_type.startsWith("authority_")) {
    return "Your reviewed task boundaries were recorded.";
  }
  if (event.verdict) {
    if (event.details?.tool === "sentinel_task_propose") {
      return event.verdict === "confirm_required"
        ? "The agent proposed a task; it waits for your confirmation and grants nothing."
        : `Task proposal rejected: ${verdictLabel(event.verdict)}.`;
    }
    return tool
      ? `${tool}: ${verdictLabel(event.verdict)}.`
      : `Decision: ${verdictLabel(event.verdict)}.`;
  }
  return "Sentinel recorded this workspace event.";
}

function proposalDescription(event: AuditEvent) {
  const details = event.details ?? {};
  const targets = Array.isArray(details.targets)
    ? details.targets.map(String)
    : [];
  const scope = targets.length
    ? `${details.operation === "write" ? "notes on" : "reads of"} ${targets.join(", ")}`
    : "a fixture task";
  switch (event.event_type) {
    case "task_proposed":
      return `The agent asked for ${scope}. Nothing was granted.`;
    case "task_proposal_confirmed":
      return `You activated ${scope} with one click; the task was rebuilt from the stored draft.`;
    case "task_proposal_dismissed":
      return details.resolution === "adjusted_in_full_form"
        ? "You chose to adjust it in the full form instead."
        : "You dismissed it. Nothing was granted.";
    case "task_proposal_superseded":
      return "A newer proposal from the agent replaced it.";
    case "task_proposal_expired":
      return "It was not confirmed in time. Nothing was granted.";
    default:
      return "Sentinel recorded a task proposal event.";
  }
}

function mcpToolSummary(event: AuditEvent) {
  const details = event.details ?? {};
  const tool = details.tool;
  if (typeof tool !== "string") return null;
  if (tool === "sentinel_task_propose") return "the task proposal tool";
  const targets = Array.isArray(details.targets) ? details.targets : [];
  const target = targets.length === 1 ? String(targets[0]) : null;
  return target ? `MCP tool ${tool} on ${target}` : `MCP tool ${tool}`;
}

function friendlyReason(reason: string) {
  if (reason.includes("target_mismatch")) {
    return "The requested location was outside the active task.";
  }
  if (reason.includes("payload_mismatch")) {
    return "The requested action changed after it was reviewed.";
  }
  if (reason.includes("production")) {
    return "Production changes require an explicit review.";
  }
  if (reason.includes("approval")) {
    return "Your approval preference required confirmation.";
  }
  return "Sentinel's safety rules required this decision.";
}

function titleCase(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1).replaceAll("_", " ");
}

function groupEventsByDay(events: AuditEvent[]) {
  const groups = new Map<string, { label: string; events: AuditEvent[] }>();
  for (const event of events) {
    const key = localDateKey(event.timestamp);
    const current = groups.get(key);
    groups.set(key, {
      label: dayLabel(event.timestamp),
      events: [...(current?.events ?? []), event],
    });
  }
  return [...groups.entries()].map(([key, value]) => ({ key, ...value }));
}

function localDateKey(value?: string) {
  if (!value) return "recent";
  const date = new Date(value);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function dayLabel(value?: string) {
  if (!value) return "Recent";
  const date = new Date(value);
  const now = new Date();
  if (date.toDateString() === now.toDateString()) return "Today";
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (date.toDateString() === yesterday.toDateString()) return "Yesterday";
  return new Intl.DateTimeFormat(undefined, {
    month: "long",
    day: "numeric",
    year: date.getFullYear() === now.getFullYear() ? undefined : "numeric",
  }).format(date);
}

function startForRange(range: string) {
  if (range === "all") return undefined;
  const milliseconds =
    range === "1h"
      ? 60 * 60 * 1000
      : range === "7d"
        ? 7 * 24 * 60 * 60 * 1000
        : 24 * 60 * 60 * 1000;
  return new Date(Date.now() - milliseconds).toISOString();
}

function formatTime(value?: string) {
  if (!value) return "";
  return new Intl.DateTimeFormat(undefined, {
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function formatTimestamp(value?: string) {
  if (!value) return "Unknown";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function sortEvents(events: AuditEvent[]) {
  return [...events].sort((left, right) => {
    if (
      left.sequence_id !== undefined &&
      left.sequence_id !== null &&
      right.sequence_id !== undefined &&
      right.sequence_id !== null &&
      left.sequence_id !== right.sequence_id
    ) {
      return right.sequence_id - left.sequence_id;
    }
    return (
      new Date(right.timestamp ?? 0).getTime() -
      new Date(left.timestamp ?? 0).getTime()
    );
  });
}
