"use client";

import { Check, CircleAlert, ShieldCheck, X } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState, type ReactNode } from "react";

import { useControl } from "@/components/control-provider";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Empty, EmptyDescription, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
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

type ApprovalState =
  | "pending"
  | "approved"
  | "denied"
  | "expired"
  | "consumed"
  | "failed";

type LocalOutcome = {
  state: ApprovalState;
  response?: ApprovalActionResponse;
  message?: string;
};

export default function ApprovalsPage() {
  const { activeContract, refresh } = useControl();
  const [known, setKnown] = useState<Record<string, PendingApprovalResponse>>({});
  const [pendingIds, setPendingIds] = useState<Set<string>>(new Set());
  const [outcomes, setOutcomes] = useState<Record<string, LocalOutcome>>({});
  const [typedTargets, setTypedTargets] = useState<Record<string, string>>({});
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

  const approvals = useMemo(
    () =>
      Object.values(known).sort(
        (left, right) =>
          new Date(right.expires_at).getTime() -
          new Date(left.expires_at).getTime(),
      ),
    [known],
  );

  async function decide(
    approval: PendingApprovalResponse,
    decision: "approve" | "deny",
  ) {
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
    <div>
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#4f6fad]">
          Approvals · {pendingIds.size} waiting
        </p>
        <h1 className="mt-2 text-[30px] font-semibold tracking-[-0.045em]">
          Review changes
        </h1>
        <p className="mt-2 max-w-2xl text-[13px] leading-6 text-[var(--subtext)]">
          Sentinel explains the outcome before anything happens.
        </p>
      </div>

      {loadError ? (
        <Alert variant="destructive" className="mt-7">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>Approval state unavailable</AlertTitle>
          <AlertDescription>{loadError}</AlertDescription>
        </Alert>
      ) : null}

      <div className="mt-10 flex flex-col gap-12">
        {approvals.length === 0 ? (
          <Empty className="min-h-[320px] border-y border-[var(--line)]">
            <ShieldCheck aria-hidden="true" size={22} />
            <EmptyTitle>No changes need review</EmptyTitle>
            <EmptyDescription>
              New approval requests will appear here before the agent can act.
            </EmptyDescription>
          </Empty>
        ) : (
          approvals.map((approval) => {
            const state = approvalState(
              approval,
              pendingIds,
              outcomes[approval.approval_id],
            );
            const needsTarget =
              approval.operation === "delete" ||
              approval.environment === "production";
            const typedTarget = typedTargets[approval.approval_id] ?? "";
            const exactTarget =
              approval.targets.length === 1 ? approval.targets[0] : null;
            const canApprove =
              state === "pending" &&
              (!needsTarget || typedTarget === exactTarget);
            const matches = matchesAuthority(approval, activeContract);
            const approvedResult = approvedOutcome(
              approval,
              outcomes[approval.approval_id]?.response,
            );

            return (
              <section
                key={approval.approval_id}
                className="mx-auto w-full max-w-[820px]"
                aria-labelledby={`approval-${approval.approval_id}`}
              >
                <div className="border-y border-[var(--line)] py-6">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#4f6fad]">
                    {stateLabel(state)}
                  </p>
                  <h2
                    id={`approval-${approval.approval_id}`}
                    className="mt-2 text-[22px] font-medium tracking-[-0.025em]"
                  >
                    {actionTitle(approval)}
                  </h2>
                  <p className="mt-2 text-[12px] text-[var(--subtext)]">
                    {matches
                      ? "This request matches your current task and workspace settings."
                      : "This request no longer matches the active task. Do not approve it."}
                  </p>
                </div>

                <div className="py-7">
                  <h3 className="text-[11px] font-semibold">What will happen</h3>
                  <ul className="mt-3">
                    <OutcomeRow
                      title={
                        approval.family === "mcp"
                          ? toolSummary(approval)
                          : operationSummary(approval.operation)
                      }
                      detail={effectSummary(approval)}
                    />
                    <OutcomeRow
                      title={locationSummary(approval)}
                      detail="The agent cannot use this approval for another location."
                    />
                    <OutcomeRow
                      title="This approval works once"
                      detail="A different or repeated change needs another review."
                    />
                  </ul>
                </div>

                <section
                  aria-labelledby={`exact-action-${approval.approval_id}`}
                  className="border-y border-[var(--line)] py-6"
                >
                  <h3
                    id={`exact-action-${approval.approval_id}`}
                    className="text-[11px] font-semibold"
                  >
                    Exact action
                  </h3>
                  <dl className="mt-4 grid gap-x-8 gap-y-5 sm:grid-cols-2">
                    {approval.family === "mcp" ? (
                      <>
                        <ExactDetail
                          label="Tool"
                          value={
                            <code className="font-mono text-[11px]">
                              {approval.tool ?? "unknown tool"}
                            </code>
                          }
                        />
                        <ExactDetail
                          label="Route"
                          value="Cursor MCP · mediated by Sentinel"
                        />
                        <ExactDetail
                          label="Exact arguments"
                          className="sm:col-span-2"
                          value={
                            <pre className="whitespace-pre-wrap break-all font-mono text-[11px]">
                              {JSON.stringify(approval.arguments, null, 2)}
                            </pre>
                          }
                        />
                      </>
                    ) : (
                      <ExactDetail
                        label="Command"
                        className="sm:col-span-2"
                        value={
                          <code className="break-all font-mono text-[11px]">
                            {approval.raw_command}
                          </code>
                        }
                      />
                    )}
                    <ExactDetail
                      label="Every target"
                      value={<ExactList values={approval.targets} />}
                    />
                    <ExactDetail
                      label="Expected effects"
                      value={<ExactList values={approval.effects} />}
                    />
                    <ExactDetail
                      label="Why Sentinel paused it"
                      className="sm:col-span-2"
                      value={<ExactList values={approval.reasons} />}
                    />
                  </dl>
                  <details className="mt-5 border-t border-[var(--line)] pt-4 text-[11px]">
                    <summary className="w-fit cursor-pointer font-medium outline-none focus-visible:ring-2 focus-visible:ring-black">
                      Authority binding
                    </summary>
                    <dl className="mt-4 grid gap-x-8 gap-y-4 text-[var(--subtext)] sm:grid-cols-2">
                      <ExactDetail label="Workspace" value={approval.workspace} />
                      <ExactDetail label="Task" value={approval.task_id} />
                      <ExactDetail
                        label="Contract"
                        value={`${approval.contract_id} · version ${approval.contract_version}`}
                      />
                      <ExactDetail
                        label="Authority epoch"
                        value={String(approval.authority_epoch)}
                      />
                      <ExactDetail
                        label="Environment"
                        value={approval.environment}
                      />
                      <ExactDetail
                        label="Expires"
                        value={new Date(approval.expires_at).toLocaleString()}
                      />
                    </dl>
                  </details>
                </section>

                <p className="pt-4 text-[11px] leading-5 text-[var(--subtext)]">
                  {confirmationExplanation(approval)}
                </p>

                {needsTarget && state === "pending" ? (
                  <div className="mt-6 border-l-2 border-[var(--main)] pl-4">
                    <label
                      htmlFor={`typed-target-${approval.approval_id}`}
                      className="text-[11px] font-semibold"
                    >
                      Type the exact target to approve
                    </label>
                    <p className="mt-1.5 break-all text-[11px] text-[var(--subtext)]">
                      {exactTarget ??
                        "This action has multiple targets and cannot be approved here."}
                    </p>
                    <Input
                      id={`typed-target-${approval.approval_id}`}
                      value={typedTarget}
                      onChange={(event) =>
                        setTypedTargets((current) => ({
                          ...current,
                          [approval.approval_id]: event.target.value,
                        }))
                      }
                      className="mt-3 max-w-xl text-[12px]"
                      autoComplete="off"
                      disabled={!exactTarget}
                    />
                  </div>
                ) : null}

                {state === "denied" ? (
                  <div className="mt-6 border-t border-[var(--line)] pt-5">
                    <p className="text-[12px] font-medium">Change denied</p>
                    <p className="mt-1 text-[11px] leading-5 text-[var(--subtext)]">
                      Nothing was executed. Update the task if its boundaries
                      were wrong, then ask the agent to submit a new request.
                    </p>
                    <Button asChild variant="secondary" size="sm" className="mt-3">
                      <Link href="/tasks">Review task</Link>
                    </Button>
                  </div>
                ) : null}

                {state === "approved" ? (
                  <Alert
                    variant={
                      approvedResult.kind === "success"
                        ? "default"
                        : "destructive"
                    }
                    className="mt-6"
                  >
                    {approvedResult.kind === "success" ? (
                      <Check aria-hidden="true" />
                    ) : (
                      <CircleAlert aria-hidden="true" />
                    )}
                    <AlertTitle>{approvedResult.title}</AlertTitle>
                    <AlertDescription>
                      {approvedResult.description}
                    </AlertDescription>
                  </Alert>
                ) : null}

                {state === "failed" ? (
                  <Alert variant="destructive" className="mt-6">
                    <CircleAlert aria-hidden="true" />
                    <AlertTitle>Outcome needs verification</AlertTitle>
                    <AlertDescription>
                      {outcomes[approval.approval_id]?.message}
                    </AlertDescription>
                  </Alert>
                ) : null}

                {state === "pending" ? (
                  <div className="mt-7 flex flex-wrap justify-end gap-3 border-t border-[var(--line)] pt-6">
                    <Button
                      variant="secondary"
                      onClick={() => decide(approval, "deny")}
                      disabled={acting !== null}
                    >
                      <X aria-hidden="true" data-icon="inline-start" />
                      Deny
                    </Button>
                    <Button
                      onClick={() => decide(approval, "approve")}
                      disabled={!canApprove || acting !== null || !matches}
                    >
                      <Check aria-hidden="true" data-icon="inline-start" />
                      {acting === approval.approval_id
                        ? "Applying decision…"
                        : "Approve exact action"}
                    </Button>
                  </div>
                ) : null}
              </section>
            );
          })
        )}
      </div>
    </div>
  );
}

function OutcomeRow({ title, detail }: { title: string; detail: string }) {
  return (
    <li className="flex gap-3 border-t border-[var(--line)] py-3.5">
      <span className="mt-0.5 grid size-5 shrink-0 place-items-center rounded-full border border-[var(--main)] bg-[var(--main-soft)] text-[10px] text-[#294d91]">
        ✓
      </span>
      <div>
        <p className="text-[12px] font-medium">{title}</p>
        <p className="mt-0.5 text-[10px] text-[var(--subtext)]">{detail}</p>
      </div>
    </li>
  );
}

function ExactDetail({
  label,
  value,
  className,
}: {
  label: string;
  value: ReactNode;
  className?: string;
}) {
  return (
    <div className={className}>
      <dt className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--faint)]">
        {label}
      </dt>
      <dd className="mt-1.5 break-all text-[11px] leading-5">{value}</dd>
    </div>
  );
}

function ExactList({ values }: { values: string[] }) {
  if (values.length === 0) return <span>None declared</span>;
  return (
    <ul className="flex flex-col gap-1">
      {values.map((value) => (
        <li key={value} className="break-all font-mono text-[10px]">
          {value}
        </li>
      ))}
    </ul>
  );
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
