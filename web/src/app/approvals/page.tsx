"use client";

import { Check, CircleAlert, X } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState, type ReactNode } from "react";

import { useControl } from "@/components/control-provider";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Empty, EmptyDescription, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import {
  COLUMN_HEAD_CLASS,
  KeyValueList,
  PageHeader,
  Panel,
  SectionHeader,
  StatusDot,
  type StatusTone,
} from "@/components/ui/layout";
import {
  approveAction,
  ControlApiError,
  denyAction,
  listApprovals,
} from "@/lib/control-api";
import type {
  ApprovalActionResponse,
  ContractRecord,
  PendingApprovalResponse,
} from "@/lib/control-types";
import { cn } from "@/lib/utils";

type ApprovalState = "pending" | "approved" | "denied" | "expired" | "consumed" | "failed";

type LocalOutcome = {
  state: ApprovalState;
  response?: ApprovalActionResponse;
  message?: string;
};

/**
 * Approvals: master-detail. The list panel on the left holds every request
 * seen this session (pending first); the detail panel on the right explains
 * the selected one in plain words and carries the decision buttons. With
 * nothing to review, one empty panel fills the space instead.
 */
export default function ApprovalsPage() {
  const { activeContract, refresh } = useControl();
  const [known, setKnown] = useState<Record<string, PendingApprovalResponse>>({});
  const [pendingIds, setPendingIds] = useState<Set<string>>(new Set());
  const [outcomes, setOutcomes] = useState<Record<string, LocalOutcome>>({});
  const [typedTargets, setTypedTargets] = useState<Record<string, string>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [acting, setActing] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const result = await listApprovals();
        if (cancelled) return;
        const nextIds = new Set(result.approvals.map((item) => item.approval_id));
        setKnown((current) => {
          const next = { ...current };
          for (const item of result.approvals) next[item.approval_id] = item;
          return next;
        });
        setPendingIds(nextIds);
        // Pin the default selection as soon as data arrives. Leaving it implicit
        // would let a later poll re-sort the list and silently swap which
        // request the Approve/Deny buttons act on.
        setSelectedId((current) => current ?? result.approvals[0]?.approval_id ?? null);
        setLoadError(null);
      } catch (error) {
        if (!cancelled) {
          setLoadError(
            error instanceof ControlApiError && error.status === 401
              ? "Your control session expired. Open a fresh pairing link."
              : "Pending approvals could not be loaded.",
          );
        }
      }
    }

    void load();
    const interval = window.setInterval(load, 5_000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const approvals = useMemo(() => {
    const items = Object.values(known).map((approval) => ({
      approval,
      state: approvalState(approval, pendingIds, outcomes[approval.approval_id]),
    }));
    // Pending first, then most recently expiring.
    return items.sort((left, right) => {
      if ((left.state === "pending") !== (right.state === "pending")) {
        return left.state === "pending" ? -1 : 1;
      }
      return (
        new Date(right.approval.expires_at).getTime() -
        new Date(left.approval.expires_at).getTime()
      );
    });
  }, [known, outcomes, pendingIds]);

  const selected =
    approvals.find((item) => item.approval.approval_id === selectedId) ?? approvals[0] ?? null;

  async function decide(approval: PendingApprovalResponse, decision: "approve" | "deny") {
    // Pin the selection so the outcome is shown here, not the next pending item.
    setSelectedId(approval.approval_id);
    setActing(approval.approval_id);
    setLoadError(null);
    try {
      const response =
        decision === "approve"
          ? await approveAction(approval.approval_id, {
              typed_target: typedTargets[approval.approval_id] || null,
            })
          : await denyAction(approval.approval_id);
      setOutcomes((current) => ({
        ...current,
        [approval.approval_id]: { state: response.status, response },
      }));
      setPendingIds((current) => {
        const next = new Set(current);
        next.delete(approval.approval_id);
        return next;
      });
      await refresh();
    } catch (error) {
      setOutcomes((current) => ({
        ...current,
        [approval.approval_id]: {
          state: "failed",
          message:
            error instanceof ControlApiError && error.status === 409
              ? "This request changed, expired, or was already used. Refresh before acting again."
              : "Sentinel did not receive a definitive result. The outcome is unknown; check Activity before retrying.",
        },
      }));
    } finally {
      setActing(null);
    }
  }

  return (
    <div className="flex min-h-[calc(100vh-52px-40px)] flex-col">
      <PageHeader
        eyebrow="Approvals"
        title={pendingIds.size === 0 ? "Nothing waiting" : `${pendingIds.size} waiting for you`}
      />

      {loadError ? (
        <Alert variant="destructive" className="mb-4">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>Approval state unavailable</AlertTitle>
          <AlertDescription>{loadError}</AlertDescription>
        </Alert>
      ) : null}

      {approvals.length === 0 ? (
        <Empty className="flex-1">
          <EmptyTitle>No changes need review</EmptyTitle>
          <EmptyDescription>
            When the agent tries a write under the active task, it pauses here until you approve
            or deny the exact action.
          </EmptyDescription>
        </Empty>
      ) : (
        <div className="grid flex-1 gap-7 lg:grid-cols-[minmax(240px,1fr)_minmax(0,2.2fr)]">
          <div className="flex min-w-0 flex-col">
            <SectionHeader id="approval-list-heading" label="Requests" className={COLUMN_HEAD_CLASS} />
            <Panel role="region" aria-labelledby="approval-list-heading" className="flex-1 py-1">
              <ul className="divide-y divide-[var(--line)]">
                {approvals.map(({ approval, state }) => (
                  <li key={approval.approval_id}>
                    <button
                      type="button"
                      aria-current={
                        selected?.approval.approval_id === approval.approval_id ? "true" : undefined
                      }
                      className={cn(
                        "grid w-full grid-cols-[minmax(0,1fr)_auto] items-start gap-x-3 px-4 py-3 text-left outline-none transition-colors hover:bg-[var(--hover)] focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-inset",
                        selected?.approval.approval_id === approval.approval_id && "bg-[var(--hover)]",
                      )}
                      onClick={() => setSelectedId(approval.approval_id)}
                    >
                      <span className="min-w-0">
                        <span className="block truncate text-[13px] font-medium">{actionTitle(approval)}</span>
                        <span className="mt-0.5 block truncate font-mono text-[11px] text-[var(--subtext)]">
                          {approval.targets[0] ?? approval.tool ?? approval.operation}
                          <span className="text-[var(--faint)]"> · #{approval.approval_id.slice(0, 8)}</span>
                        </span>
                      </span>
                      <StatusDot tone={stateTone(state)} className="text-[11px] text-[var(--subtext)]">
                        {stateWord(state)}
                      </StatusDot>
                    </button>
                  </li>
                ))}
              </ul>
            </Panel>
          </div>

          <div className="flex min-w-0 flex-col">
            <SectionHeader id="approval-detail-heading" label="Review" className={COLUMN_HEAD_CLASS} />
            {selected ? (
              <ApprovalDetail
                approval={selected.approval}
                state={selected.state}
                outcome={outcomes[selected.approval.approval_id]}
                activeContract={activeContract}
                typedTarget={typedTargets[selected.approval.approval_id] ?? ""}
                onTypedTarget={(value) =>
                  setTypedTargets((current) => ({ ...current, [selected.approval.approval_id]: value }))
                }
                acting={acting !== null}
                onDecide={(decision) => decide(selected.approval, decision)}
              />
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}

function ApprovalDetail({
  approval,
  state,
  outcome,
  activeContract,
  typedTarget,
  onTypedTarget,
  acting,
  onDecide,
}: {
  approval: PendingApprovalResponse;
  state: ApprovalState;
  outcome?: LocalOutcome;
  activeContract: ContractRecord | null;
  typedTarget: string;
  onTypedTarget: (value: string) => void;
  acting: boolean;
  onDecide: (decision: "approve" | "deny") => void;
}) {
  const needsTarget = approval.operation === "delete" || approval.environment === "production";
  const exactTarget = approval.targets.length === 1 ? approval.targets[0] : null;
  const canApprove = state === "pending" && (!needsTarget || typedTarget === exactTarget);
  const matches = matchesAuthority(approval, activeContract);
  const approvedResult = approvedOutcome(approval, outcome?.response);
  const headingId = `approval-${approval.approval_id}`;

  return (
    <Panel role="region" aria-labelledby={headingId} className="flex flex-1 flex-col">
      <div className="px-5 py-4">
        <StatusDot tone={stateTone(state)} className="text-[12px] text-[var(--subtext)]">
          {stateLabel(state)}
        </StatusDot>
        <h2 id={headingId} className="mt-1.5 text-[20px] font-semibold leading-[1.25] tracking-[-0.02em]">
          {actionTitle(approval)}
        </h2>
        <p className="mt-1.5 text-[13px] text-[var(--subtext)]">
          {matches
            ? "This request matches your current task and workspace settings."
            : "This request no longer matches the active task. Do not approve it."}
        </p>
      </div>

      <section aria-labelledby={`${headingId}-happens`} className="border-t border-[var(--line)] px-5 py-4">
        <h3 id={`${headingId}-happens`} className="text-[12px] font-semibold">
          What will happen
        </h3>
        <ul className="mt-2 flex flex-col gap-2">
          <OutcomeRow
            title={approval.family === "mcp" ? toolSummary(approval) : operationSummary(approval.operation)}
            detail={effectSummary(approval)}
          />
          <OutcomeRow
            title={locationSummary(approval)}
            detail="The agent cannot use this approval for another location."
          />
          <OutcomeRow title="This approval works once" detail="A different or repeated change needs another review." />
        </ul>
        <p className="mt-3 text-[12px] leading-5 text-[var(--subtext)]">{confirmationExplanation(approval)}</p>
      </section>

      <section aria-labelledby={`${headingId}-exact`} className="border-t border-[var(--line)] px-5 py-4">
        <h3 id={`${headingId}-exact`} className="text-[12px] font-semibold">
          Exact action
        </h3>
        <KeyValueList
          className="mt-3"
          labelWidth="132px"
          items={[
            ...(approval.family === "mcp"
              ? [
                  { label: "Tool", value: <Mono>{approval.tool ?? "unknown tool"}</Mono> },
                  { label: "Route", value: "Cursor MCP · mediated by Sentinel" },
                  {
                    label: "Exact arguments",
                    value: (
                      <pre className="whitespace-pre-wrap break-all font-mono text-[11px] font-normal leading-5">
                        {JSON.stringify(approval.arguments, null, 2)}
                      </pre>
                    ),
                  },
                ]
              : [{ label: "Command", value: <Mono>{approval.raw_command}</Mono> }]),
            { label: "Every target", value: <MonoList values={approval.targets} /> },
            { label: "Expected effects", value: <MonoList values={approval.effects} /> },
            { label: "Why it paused", value: <MonoList values={approval.reasons} /> },
          ]}
        />
        <details className="mt-4 border-t border-[var(--line)] pt-3">
          <summary className="w-fit cursor-pointer text-[12px] font-medium outline-none focus-visible:ring-2 focus-visible:ring-black">
            Authority binding
          </summary>
          <KeyValueList
            className="mt-3 text-[12px]"
            labelWidth="132px"
            items={[
              { label: "Workspace", value: <Mono>{approval.workspace}</Mono> },
              { label: "Task", value: <Mono>{approval.task_id}</Mono> },
              { label: "Contract", value: <Mono>{`${approval.contract_id} · v${approval.contract_version}`}</Mono> },
              { label: "Authority epoch", value: <Mono>{String(approval.authority_epoch)}</Mono> },
              { label: "Environment", value: <span className="capitalize">{approval.environment}</span> },
              { label: "Expires", value: new Date(approval.expires_at).toLocaleString() },
            ]}
          />
        </details>
      </section>

      {state === "denied" ? (
        <div className="border-t border-[var(--line)] px-5 py-4">
          <p className="text-[13px] font-medium">Change denied</p>
          <p className="mt-1 text-[12px] leading-5 text-[var(--subtext)]">
            Nothing was executed. Update the task if its boundaries were wrong, then ask the agent
            to submit a new request.
          </p>
          <Button asChild variant="secondary" size="sm" className="mt-3">
            <Link href="/tasks">Review task</Link>
          </Button>
        </div>
      ) : null}

      {state === "approved" ? (
        <div className="border-t border-[var(--line)] px-5 py-4">
          <Alert variant={approvedResult.kind === "success" ? "default" : "destructive"}>
            {approvedResult.kind === "success" ? <Check aria-hidden="true" /> : <CircleAlert aria-hidden="true" />}
            <AlertTitle>{approvedResult.title}</AlertTitle>
            <AlertDescription>{approvedResult.description}</AlertDescription>
          </Alert>
        </div>
      ) : null}

      {state === "failed" ? (
        <div className="border-t border-[var(--line)] px-5 py-4">
          <Alert variant="destructive">
            <CircleAlert aria-hidden="true" />
            <AlertTitle>Outcome needs verification</AlertTitle>
            <AlertDescription>{outcome?.message}</AlertDescription>
          </Alert>
        </div>
      ) : null}

      {state === "pending" ? (
        <div className="mt-auto border-t border-[var(--line)] px-5 py-4">
          {needsTarget ? (
            <div className="mb-4">
              <label htmlFor={`typed-target-${approval.approval_id}`} className="text-[12px] font-medium">
                Type the exact target to approve
              </label>
              <p className="mt-1 break-all font-mono text-[11px] text-[var(--subtext)]">
                {exactTarget ?? "This action has multiple targets and cannot be approved here."}
              </p>
              <Input
                id={`typed-target-${approval.approval_id}`}
                value={typedTarget}
                onChange={(event) => onTypedTarget(event.target.value)}
                className="mt-2 max-w-xl font-mono text-[12px]"
                autoComplete="off"
                disabled={!exactTarget}
              />
            </div>
          ) : null}
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="secondary" onClick={() => onDecide("deny")} disabled={acting}>
              <X aria-hidden="true" data-icon="inline-start" />
              Deny
            </Button>
            <Button onClick={() => onDecide("approve")} disabled={!canApprove || acting || !matches}>
              <Check aria-hidden="true" data-icon="inline-start" />
              {acting ? "Applying decision…" : "Approve exact action"}
            </Button>
          </div>
        </div>
      ) : null}
    </Panel>
  );
}

function OutcomeRow({ title, detail }: { title: string; detail: string }) {
  return (
    <li className="grid grid-cols-[14px_minmax(0,1fr)] gap-x-2.5">
      <Check aria-hidden="true" size={13} strokeWidth={2} className="mt-1" />
      <div>
        <p className="text-[13px] font-medium">{title}</p>
        <p className="text-[12px] text-[var(--subtext)]">{detail}</p>
      </div>
    </li>
  );
}

function Mono({ children }: { children: ReactNode }) {
  return <code className="break-all font-mono text-[12px] font-normal">{children}</code>;
}

function MonoList({ values }: { values: string[] }) {
  if (values.length === 0) return <span className="font-normal text-[var(--subtext)]">None declared</span>;
  return (
    <ul className="flex flex-col gap-0.5">
      {values.map((value) => (
        <li key={value} className="break-all font-mono text-[12px] font-normal">
          {value}
        </li>
      ))}
    </ul>
  );
}

function stateTone(state: ApprovalState): StatusTone {
  return state === "pending"
    ? "warn"
    : state === "approved"
      ? "ok"
      : state === "denied" || state === "failed"
        ? "off"
        : "muted";
}

function stateWord(state: ApprovalState) {
  return { pending: "Waiting", approved: "Approved", denied: "Denied", expired: "Expired", consumed: "Used", failed: "Unknown" }[state];
}
function matchesAuthority(
  approval: PendingApprovalResponse,
  activeContract: ContractRecord | null,
) {
  return Boolean(
    activeContract &&
      activeContract.task_id === approval.task_id &&
      activeContract.contract_id === approval.contract_id &&
      activeContract.version === approval.contract_version &&
      activeContract.authority_epoch === approval.authority_epoch &&
      activeContract.contract.environment === approval.environment &&
      activeContract.contract.allowed_operations.includes(
        approval.operation as ContractRecord["contract"]["allowed_operations"][number],
      ) &&
      approval.targets.every((target) =>
        activeContract.contract.exact_targets.includes(target),
      ) &&
      approval.effects.every((effect) =>
        (activeContract.contract.allowed_effects ?? []).includes(effect),
      ),
  );
}

function actionTitle(approval: PendingApprovalResponse) {
  const target = approval.targets.length === 1 ? shortTarget(approval.targets[0]) : null;
  if (approval.family === "mcp") {
    const noun = approval.tool === "sentinel_issue_add_note" ? "Add a note to" : "Use a tool on";
    return target ? `${noun} issue ${target}` : `${noun} the requested issue`;
  }
  const verb = {
    read: "Read",
    write: "Change",
    delete: "Delete",
    execute: "Run",
    network: "Connect to",
    external_communication: "Send",
    credential_access: "Access",
  }[approval.operation] ?? "Perform";
  return target ? `${verb} ${target}` : `${verb} this requested action`;
}

function toolSummary(approval: PendingApprovalResponse) {
  if (approval.tool === "sentinel_issue_add_note") {
    return "One note will be added to the local fixture issue";
  }
  if (approval.tool === "sentinel_issue_read") {
    return "The fixture issue will be read";
  }
  return "The requested tool call will be performed through Sentinel";
}

function operationSummary(operation: string) {
  return {
    read: "Information will be read",
    write: "A file will be created or changed",
    delete: "A file will be deleted",
    execute: "A program will run",
    network: "A network connection will be used",
    external_communication: "A message will be sent",
    credential_access: "Credentials will be accessed",
  }[operation] ?? "The requested change will be performed";
}

function effectSummary(approval: PendingApprovalResponse) {
  if (approval.effects.length === 0) return "No additional effects were declared.";
  if (approval.effects.length === 1) {
    return `Expected effect: ${approval.effects[0].replaceAll("_", " ")}.`;
  }
  return `${approval.effects.length} expected effects are included in this request.`;
}

function locationSummary(approval: PendingApprovalResponse) {
  if (approval.targets.length === 0) return "The request stays inside this workspace";
  if (approval.targets.length === 1) {
    return `The change is limited to ${shortTarget(approval.targets[0])}`;
  }
  return `The change is limited to ${approval.targets.length} reviewed locations`;
}

function shortTarget(value: string) {
  const parts = value.split("/").filter(Boolean);
  if (parts.length <= 2) return value;
  return parts.slice(-2).join("/");
}

function confirmationExplanation(approval: PendingApprovalResponse) {
  if (approval.environment === "production") {
    return "Sentinel is asking because this change affects production and requires your confirmation.";
  }
  if (approval.operation === "delete") {
    return "Sentinel is asking because deleting a file cannot be undone automatically.";
  }
  return "Sentinel is asking because your preferences require a review before this kind of change.";
}

function approvedOutcome(
  approval: PendingApprovalResponse,
  response?: ApprovalActionResponse,
) {
  const retry = response?.retry;
  if (!retry || retry.verdict !== "allow") {
    return {
      kind: "blocked" as const,
      title: "Approved; retry blocked",
      description:
        "Your approval was recorded, but Sentinel did not admit the retry. Review Activity before trying again.",
    };
  }
  if (approval.family === "mcp") {
    // MCP writes are applied by Sentinel itself, so there is no shell
    // execution record; the fixture reports its own outcome in the reasons.
    const applied = (retry.reasons ?? []).includes("mcp:approved_write_applied");
    const fixtureFailed = (retry.reasons ?? []).some(
      (reason) => reason.startsWith("fixture:") && reason !== "fixture:succeeded",
    );
    if (!applied || fixtureFailed) {
      return {
        kind: "failed" as const,
        title: "Approved; write did not complete",
        description:
          "Sentinel admitted the exact action, but the tracker did not confirm the write. Review Activity before trying again.",
      };
    }
    return {
      kind: "success" as const,
      title: "Approved and applied",
      description:
        "Sentinel used this approval once and applied the exact note to the issue.",
    };
  }
  if (
    !retry.execution ||
    retry.execution.error ||
    retry.execution.timed_out ||
    retry.execution.exit_code !== 0
  ) {
    return {
      kind: "failed" as const,
      title: "Approved; execution failed",
      description:
        "Sentinel admitted the exact action, but the executor did not complete it successfully. Review Activity before trying again.",
    };
  }
  return {
    kind: "success" as const,
    title: "Approved and executed",
    description:
      "Sentinel used this approval once and completed the exact action successfully.",
  };
}

function stateLabel(state: ApprovalState) {
  return {
    pending: "Waiting for your review",
    approved: "Approved",
    denied: "Denied",
    expired: "Expired",
    consumed: "No longer available",
    failed: "Outcome needs verification",
  }[state];
}

function approvalState(
  approval: PendingApprovalResponse,
  pendingIds: Set<string>,
  outcome?: LocalOutcome,
): ApprovalState {
  if (outcome) return outcome.state;
  if (new Date(approval.expires_at).getTime() <= Date.now()) return "expired";
  return pendingIds.has(approval.approval_id) ? "pending" : "consumed";
}
