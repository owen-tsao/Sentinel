"use client";

import {
  Check,
  CircleAlert,
  FileCheck2,
  FileX2,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [taskId, setTaskId] = useState("");
  const [eventType, setEventType] = useState("all");
  const [verdict, setVerdict] = useState("all");
  const [timeRange, setTimeRange] = useState("24h");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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
      const nextEvents = sortEvents(response.events);
      setEvents(nextEvents);
      setSelected((current) =>
        current
          ? nextEvents.find((event) => event.event_id === current.event_id) ??
            null
          : null,
      );
    } catch (caught) {
      setError(
        caught instanceof ControlApiError && caught.status === 401
          ? "Your control session expired. Open a fresh pairing link."
          : "Activity could not be loaded.",
      );
    } finally {
      setLoading(false);
    }
  }, [eventType, taskId, timeRange, verdict]);

  useEffect(() => {
    let cancelled = false;
    void getAuditEvents({ startTime: startForRange("24h") })
      .then((response) => {
        if (!cancelled) {
          const nextEvents = sortEvents(response.events);
          setEvents(nextEvents);
          setSelected((current) =>
            current
              ? nextEvents.find(
                  (event) => event.event_id === current.event_id,
                ) ?? null
              : null,
          );
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setError(
            caught instanceof ControlApiError && caught.status === 401
              ? "Your control session expired. Open a fresh pairing link."
              : "Activity could not be loaded.",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const groups = useMemo(() => groupEventsByDay(events), [events]);
  const summary = useMemo(
    () => ({
      total: events.length,
      approvals: events.filter(
        (event) => event.event_type === "exact_action_approved",
      ).length,
      blocked: events.filter((event) => event.verdict === "block").length,
      executions: events.filter(
        (event) => event.event_type === "post_execution",
      ).length,
    }),
    [events],
  );

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#4f6fad]">
            Activity
          </p>
          <h1 className="mt-2 text-[30px] font-semibold tracking-[-0.045em]">
            What happened
          </h1>
          <p className="mt-2 max-w-2xl text-[13px] leading-6 text-[var(--subtext)]">
            A simple history of decisions and changes across your workspace.
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={load} disabled={loading}>
          <RefreshCw aria-hidden="true" data-icon="inline-start" />
          {loading ? "Refreshing…" : "Refresh"}
        </Button>
      </div>

      {error ? (
        <Alert variant="destructive" className="mt-7">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>Activity unavailable</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <section
        aria-label="Activity summary"
        className="mt-9 grid grid-cols-2 border-y border-[var(--line)] sm:grid-cols-4 sm:divide-x sm:divide-[var(--line)]"
      >
        <SummaryMetric label="Events shown" value={summary.total} />
        <SummaryMetric label="Approvals shown" value={summary.approvals} />
        <SummaryMetric label="Blocked shown" value={summary.blocked} />
        <SummaryMetric label="Executions shown" value={summary.executions} />
      </section>
      <p className="mt-2 text-[10px] text-[var(--faint)]">
        Summary covers the latest 200 matching events.
      </p>

      <section aria-labelledby="activity-filters" className="mt-8">
        <h2 id="activity-filters" className="sr-only">
          Activity filters
        </h2>
        <div className="grid items-end gap-4 border-b border-[var(--line)] pb-6 md:grid-cols-2 xl:grid-cols-[1.1fr_0.9fr_0.9fr_0.8fr_auto]">
          <Filter label="Task reference" htmlFor="audit-task">
            <Input
              id="audit-task"
              value={taskId}
              onChange={(event) => setTaskId(event.target.value)}
              placeholder="Search a task"
              className="h-10 text-[12px]"
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
                  <SelectItem value="confirm_required">
                    Asked for approval
                  </SelectItem>
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
          <Button onClick={load} disabled={loading}>
            Apply filters
          </Button>
        </div>
      </section>

      <div className="mt-7 grid gap-10 xl:grid-cols-[minmax(0,1fr)_300px]">
        <div>
          {!loading && events.length === 0 ? (
            <div className="border-y border-[var(--line)] py-12 text-center">
              <p className="text-[13px] font-medium">No matching activity</p>
              <p className="mt-1 text-[11px] text-[var(--subtext)]">
                Try a wider time range or clear a filter.
              </p>
            </div>
          ) : (
            groups.map((group) => (
              <section
                key={group.key}
                className="mb-8"
                aria-labelledby={`day-${group.key}`}
              >
                <h2
                  id={`day-${group.key}`}
                  className="mb-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--faint)]"
                >
                  {group.label}
                </h2>
                {group.events.map((event) => (
                  <ActivityRow
                    key={event.event_id}
                    event={event}
                    selected={selected?.event_id === event.event_id}
                    onSelect={() => setSelected(event)}
                  />
                ))}
              </section>
            ))
          )}
        </div>

        <aside className="border-t border-[var(--line)] pt-5 xl:border-l xl:border-t-0 xl:pl-7 xl:pt-0">
          {selected ? (
            <EventDetail event={selected} />
          ) : (
            <div>
              <h2 className="text-[11px] font-semibold">Activity details</h2>
              <p className="mt-2 text-[11px] leading-5 text-[var(--subtext)]">
                Choose an item to see why it happened.
              </p>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function SummaryMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="px-4 py-4 first:pl-0">
      <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--faint)]">
        {label}
      </p>
      <p className="mt-1 font-mono text-[18px] font-medium tabular-nums">
        {value}
      </p>
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
    <button
      type="button"
      aria-label={`View ${event.event_type} event sequence ${
        event.sequence_id ?? "pending"
      }`}
      className={cn(
        "grid min-h-[68px] w-full grid-cols-[42px_minmax(0,1fr)_auto] items-center gap-3.5 border-t border-[var(--line)] px-0 text-left outline-none transition-colors hover:bg-[var(--main-faint)] focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-inset",
        selected && "bg-[var(--main-soft)]",
      )}
      onClick={onSelect}
    >
      <span className="grid size-[34px] place-items-center rounded-[5px] bg-[var(--main-soft)] text-[#294d91]">
        <EventIcon event={event} />
      </span>
      <span>
        <span className="block text-[12px] font-medium">
          {eventLabel(event.event_type)}
        </span>
        <span className="mt-0.5 block text-[10px] text-[var(--subtext)]">
          {eventDescription(event)}
        </span>
      </span>
      <time className="pr-2 text-[10px] text-[var(--faint)]">
        {formatTime(event.timestamp)}
      </time>
    </button>
  );
}

function EventDetail({ event }: { event: AuditEvent }) {
  return (
    <div>
      <div className="flex items-start justify-between gap-4">
        <h2 className="text-[11px] font-semibold">Activity details</h2>
        {event.sequence_id ? (
          <span className="text-[9px] text-[var(--faint)]">
            #{event.sequence_id}
          </span>
        ) : null}
      </div>
      <p className="mt-4 text-[14px] font-medium">
        {eventLabel(event.event_type)}
      </p>
      <p className="mt-1 text-[11px] leading-5 text-[var(--subtext)]">
        {eventDescription(event)}
      </p>
      <dl className="mt-5">
        <Detail label="When" value={formatTimestamp(event.timestamp)} />
        <Detail
          label="Decision"
          value={event.verdict ? verdictLabel(event.verdict) : "Recorded"}
        />
        <Detail
          label="Environment"
          value={event.environment ? titleCase(event.environment) : "Current workspace"}
        />
      </dl>
      {event.reason_codes?.length ? (
        <div className="mt-5 border-t border-[var(--line)] pt-4">
          <p className="text-[10px] font-semibold uppercase tracking-[0.07em] text-[var(--faint)]">
            Why
          </p>
          <ul className="mt-2 flex flex-col gap-2">
            {event.reason_codes.map((reason) => (
              <li key={reason} className="text-[11px] leading-5 text-[var(--subtext)]">
                {friendlyReason(reason)}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4 border-t border-[var(--line)] py-3 text-[10px]">
      <dt className="text-[var(--faint)]">{label}</dt>
      <dd className="text-right text-[var(--subtext)]">{value}</dd>
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
    <div className="flex flex-col gap-2">
      <label htmlFor={htmlFor} className="text-[10px] font-medium">
        {label}
      </label>
      {children}
    </div>
  );
}

function EventIcon({ event }: { event: AuditEvent }) {
  if (event.event_type === "exact_action_denied" || event.verdict === "block") {
    return <FileX2 aria-hidden="true" size={15} />;
  }
  if (
    event.event_type === "exact_action_approved" ||
    event.event_type === "post_execution"
  ) {
    return <Check aria-hidden="true" size={15} />;
  }
  if (event.event_type.startsWith("authority_")) {
    return <ShieldCheck aria-hidden="true" size={15} />;
  }
  return <FileCheck2 aria-hidden="true" size={15} />;
}

function eventLabel(eventType: string) {
  return {
    authority_transition_prepared: "Task update prepared",
    authority_transition_completed: "Task settings updated",
    pre_decision: "Change reviewed",
    decision: "Safety decision made",
    exact_action_approved: "You approved a change",
    exact_action_denied: "You denied a change",
    execution_admitted: "Approved change started",
    post_execution: "Change completed",
  }[eventType] ?? "Workspace activity";
}

function eventDescription(event: AuditEvent) {
  const tool = mcpToolSummary(event);
  if (event.event_type === "exact_action_denied") return "Nothing was changed.";
  if (event.event_type === "exact_action_approved") {
    return "The approval can be used once.";
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
    return tool
      ? `${tool}: ${verdictLabel(event.verdict)}.`
      : `Decision: ${verdictLabel(event.verdict)}.`;
  }
  return "Sentinel recorded this workspace event.";
}

function mcpToolSummary(event: AuditEvent) {
  const details = event.details ?? {};
  const tool = details.tool;
  if (typeof tool !== "string") return null;
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

function verdictLabel(verdict: NonNullable<AuditEvent["verdict"]>) {
  return {
    allow: "Allowed",
    warn: "Warning",
    confirm_required: "Asked for approval",
    block: "Blocked",
  }[verdict];
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
