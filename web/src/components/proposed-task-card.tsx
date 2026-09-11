"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { useControl } from "@/components/control-provider";
import { Button } from "@/components/ui/button";
import { Chip, Ticket, TicketFacts, TicketFoot, TicketHead, TicketSeal } from "@/components/ui/ticket";
import {
  adjustProposal,
  confirmProposal,
  ControlApiError,
  dismissProposal,
  PROPOSAL_PREFILL_KEY,
} from "@/lib/control-api";
import type { TaskProposalResponse } from "@/lib/control-types";

/**
 * The compact confirmation for an agent-proposed task, rendered as the ticket
 * so the focus slot looks the same before and after activation.
 *
 * Everything shown comes from the server-stored draft. The Activate request
 * sends only the draft ID (plus the active task ID as a stale-view guard), so
 * nothing this component renders or holds can change what is granted.
 */
export function ProposedTaskCard({
  proposal,
}: {
  proposal: TaskProposalResponse;
}) {
  const router = useRouter();
  const { activeContract, refresh } = useControl();
  const [pending, setPending] = useState<"activate" | "adjust" | "dismiss" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(interval);
  }, []);

  async function run(kind: "activate" | "adjust" | "dismiss") {
    setPending(kind);
    setError(null);
    try {
      if (kind === "activate") {
        await confirmProposal(proposal.draft_id, {
          expected_active_task_id: activeContract?.task_id ?? null,
        });
      } else if (kind === "dismiss") {
        await dismissProposal(proposal.draft_id);
      } else {
        const prefill = await adjustProposal(proposal.draft_id);
        window.sessionStorage.setItem(PROPOSAL_PREFILL_KEY, JSON.stringify(prefill));
        await refresh();
        router.push("/tasks");
        return;
      }
      await refresh();
    } catch (caught) {
      setError(proposalError(caught));
      await refresh();
    } finally {
      setPending(null);
    }
  }

  return (
    <Ticket className="flex-1" aria-labelledby="proposed-task-heading">
      <TicketHead
        eyebrow="Proposed task · Awaiting your confirmation"
        title={proposal.objective}
        titleId="proposed-task-heading"
        meta={
          <>
            Proposed by the agent {relativeTime(proposal.created_at, now)}; Sentinel has
            not verified this is your request.
            {proposal.proposal_number > 1
              ? ` Proposal ${proposal.proposal_number} this session.`
              : ""}
          </>
        }
        seal={<TicketSeal state="Proposed" mark="dot" />}
      />

      <TicketFacts
        items={[
          {
            label: "Operation",
            value: proposal.operation === "write" ? "Read and add notes" : "Read only",
          },
          {
            label: `Issues (${proposal.exact_targets.length})`,
            value: (
              <span className="flex flex-wrap gap-y-1">
                {proposal.exact_targets.map((target) => (
                  <Chip key={target}>{target}</Chip>
                ))}
              </span>
            ),
          },
          { label: "Environment", value: proposal.environment },
          { label: "Allowed changes", value: proposal.allowed_effects.join(", ") },
          {
            label: "Task expires",
            value: `${proposal.task_duration_minutes} minutes after activation`,
          },
        ]}
      />

      {proposal.replaces_active_task ? (
        <p className="mt-3 text-[13px] font-semibold leading-5">
          Activating replaces your current task; its pending approvals will be cleared.
        </p>
      ) : null}

      {error ? (
        <p role="alert" className="mt-3 rounded-[6px] border-[1.5px] border-black bg-white px-3 py-2 text-[12px] leading-5 text-[var(--danger)]">
          {error}
        </p>
      ) : null}

      <TicketFoot
        note={
          <>
            This proposal grants nothing until you activate it. Expires{" "}
            {relativeTime(proposal.proposal_expires_at, now, { future: true })}.
          </>
        }
        actions={
          <>
            <Button variant="quiet" disabled={pending !== null} onClick={() => run("dismiss")}>
              {pending === "dismiss" ? "Dismissing…" : "Dismiss"}
            </Button>
            <Button variant="secondary" disabled={pending !== null} onClick={() => run("adjust")}>
              {pending === "adjust" ? "Opening…" : "Adjust in full form"}
            </Button>
            <Button variant="raised" disabled={pending !== null} onClick={() => run("activate")}>
              {pending === "activate" ? "Activating…" : "Activate"}
            </Button>
          </>
        }
      />
    </Ticket>
  );
}

function relativeTime(iso: string, now: number, options: { future?: boolean } = {}) {
  const delta = new Date(iso).getTime() - now;
  const minutes = Math.round(Math.abs(delta) / 60_000);
  if (options.future) {
    if (delta <= 0) return "now";
    return minutes < 1 ? "in under a minute" : `in ${minutes} minute${minutes === 1 ? "" : "s"}`;
  }
  if (minutes < 1) return "just now";
  return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
}

function proposalError(error: unknown) {
  if (error instanceof ControlApiError) {
    if (error.status === 401) return "Control session expired. Open a fresh pairing link.";
    if (error.status === 409) {
      return "This proposal is no longer current (it was replaced, expired, or your view was stale). Refreshed.";
    }
    if (error.status === 404) return "This proposal no longer exists. Refreshed.";
    if (error.status === 422) return "The proposal no longer fits the startup ceiling and cannot be activated.";
  }
  return "The action could not be completed.";
}
