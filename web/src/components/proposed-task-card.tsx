"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { useControl } from "@/components/control-provider";
import { Button } from "@/components/ui/button";
import {
  adjustProposal,
  confirmProposal,
  ControlApiError,
  dismissProposal,
  PROPOSAL_PREFILL_KEY,
} from "@/lib/control-api";
import type { TaskProposalResponse } from "@/lib/control-types";

const sectionLabelClass =
  "text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--faint)]";

/**
 * The compact confirmation for an agent-proposed task.
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
    <section
      aria-labelledby="proposed-task-heading"
      className="rounded-[5px] border-2 border-black bg-[var(--main-soft)] p-5 shadow-[4px_4px_0_0_#000]"
    >
      <p className={sectionLabelClass}>Proposed task</p>
      <h2 id="proposed-task-heading" className="mt-2 text-[17px] font-semibold leading-6">
        {proposal.objective}
      </h2>
      <p className="mt-1 text-[11px] leading-5 text-[var(--subtext)]">
        Proposed by the agent {relativeTime(proposal.created_at, now)}; Sentinel has
        not verified this is your request.
        {proposal.proposal_number > 1
          ? ` Proposal ${proposal.proposal_number} this session.`
          : ""}
      </p>

      <dl className="mt-4 divide-y divide-[rgba(0,0,0,0.12)] text-[11px]">
        <Fact label="Operation" value={proposal.operation === "write" ? "Read and add notes" : "Read only"} />
        <div className="py-2.5">
          <dt className="text-[var(--subtext)]">
            Issues ({proposal.exact_targets.length})
          </dt>
          <dd className="mt-1.5 flex flex-wrap gap-1.5">
            {proposal.exact_targets.map((target) => (
              <span
                key={target}
                className="rounded-[3px] border border-black/25 bg-white px-1.5 py-0.5 font-mono text-[11px]"
              >
                {target}
              </span>
            ))}
          </dd>
        </div>
        <Fact label="Environment" value={proposal.environment} />
        <Fact label="Allowed changes" value={proposal.allowed_effects.join(", ")} />
        <Fact label="Task expires" value={`${proposal.task_duration_minutes} minutes after activation`} />
      </dl>

      {proposal.replaces_active_task ? (
        <p className="mt-3 text-[11px] leading-5 font-medium">
          Activating replaces your current task; its pending approvals will be cleared.
        </p>
      ) : null}

      {error ? (
        <p role="alert" className="mt-3 text-[11px] leading-5 text-[#8a1c1c]">
          {error}
        </p>
      ) : null}

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <Button size="sm" disabled={pending !== null} onClick={() => run("activate")}>
          {pending === "activate" ? "Activating…" : "Activate"}
        </Button>
        <Button
          size="sm"
          variant="secondary"
          disabled={pending !== null}
          onClick={() => run("adjust")}
        >
          {pending === "adjust" ? "Opening…" : "Adjust in full form"}
        </Button>
        <button
          type="button"
          disabled={pending !== null}
          onClick={() => run("dismiss")}
          className="link-draw text-[11px] text-[var(--subtext)] hover:text-[var(--ink)] disabled:opacity-60"
        >
          {pending === "dismiss" ? "Dismissing…" : "Dismiss"}
        </button>
      </div>
      <p className="mt-3 text-[10px] leading-4 text-[var(--faint)]">
        This proposal grants nothing until you activate it. Expires{" "}
        {relativeTime(proposal.proposal_expires_at, now, { future: true })}.
      </p>
    </section>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-5 py-2.5">
      <dt className="text-[var(--subtext)]">{label}</dt>
      <dd className="font-medium">{value}</dd>
    </div>
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
