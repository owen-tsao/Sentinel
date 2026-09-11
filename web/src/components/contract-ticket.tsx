"use client";

import { useEffect, useRef } from "react";

import { Button } from "@/components/ui/button";
import {
  Chip,
  Ticket,
  TicketFacts,
  TicketFoot,
  TicketHead,
  TicketSeal,
} from "@/components/ui/ticket";
import type { ContractRecord } from "@/lib/control-types";

export type ContractPreview = {
  operation: string;
  environment: string;
  targets: string[];
  expiresInMinutes: number | null;
};

/**
 * The right-hand ticket on the Tasks page. It is the same object the Overview
 * shows, so the user sees the contract take shape as they fill the form:
 * white while drafting or ready, blue once it is the active task.
 */
export function ContractTicket({
  stage,
  preview,
  contract,
  onActivate,
  activating,
  replacesActive = false,
  paint = false,
  className,
}: {
  stage: "empty" | "draft" | "ready" | "active";
  preview: ContractPreview | null;
  contract: ContractRecord | null;
  onActivate?: () => void;
  activating?: boolean;
  /** True when another task is active and activating this one would replace it. */
  replacesActive?: boolean;
  /** Sweep the blue in; true only right after this ticket was activated. */
  paint?: boolean;
  className?: string;
}) {
  if (stage === "empty") {
    return (
      <Ticket tone="idle" className={className} aria-labelledby="contract-ticket-title">
        <div className="flex items-start justify-between gap-6">
          <p className="text-[10px] font-semibold uppercase tracking-[0.12em] opacity-80">
            Sentinel authorization · Task contract
          </p>
          <TicketSeal state="Draft" mark="dot" />
        </div>
        <div className="flex flex-1 flex-col items-center justify-center py-10 text-center">
          <h2
            id="contract-ticket-title"
            className="text-[24px] font-semibold leading-[1.2] tracking-[-0.03em]"
          >
            No task drafted
          </h2>
          <p className="mt-2 max-w-[40ch] text-[13px] leading-5 text-[var(--subtext)]">
            Describe the goal on the left. The contract you confirm appears here before
            anything is activated.
          </p>
        </div>
      </Ticket>
    );
  }

  const facts = contract
    ? {
        title: contract.contract.objective,
        operation: contract.contract.allowed_operations.join(", "),
        environment: contract.contract.environment,
        targets: contract.contract.exact_targets,
        expires: `${formatMinutes(contract.expires_at)} · ${formatClock(contract.expires_at)}`,
      }
    : {
        title: draftTitle(preview),
        operation: preview?.operation || "—",
        environment: preview?.environment || "—",
        targets: preview?.targets ?? [],
        expires:
          preview?.expiresInMinutes && preview.expiresInMinutes > 0
            ? `${preview.expiresInMinutes} min after activation`
            : "—",
      };

  const seal =
    stage === "active" ? (
      <TicketSeal state="Active" />
    ) : (
      <TicketSeal state={stage === "ready" ? "Ready" : "Draft"} mark="dot" />
    );

  return (
    <Ticket
      tone={stage === "active" ? "active" : "idle"}
      paint={paint}
      className={className}
      aria-labelledby="contract-ticket-title"
    >
      <TicketHead
        eyebrow="Sentinel authorization · Task contract"
        title={facts.title}
        titleId="contract-ticket-title"
        meta={
          stage === "active"
            ? `Activated ${formatClock(contract?.created_at)} · Approval mode is on.`
            : stage === "ready"
              ? "Confirmed. Nothing is granted until you activate it."
              : "Draft. Confirm the settings to lock this contract."
        }
        seal={seal}
      />
      <TicketFacts
        items={[
          { label: "Operation", value: <span className="capitalize">{facts.operation.replaceAll("_", " ")}</span> },
          { label: "Environment", value: <span className="capitalize">{facts.environment}</span> },
          {
            label: "Targets",
            value: facts.targets.length ? (
              <span className="flex flex-wrap gap-y-1">
                {facts.targets.map((target) => (
                  <Chip key={target}>{target}</Chip>
                ))}
              </span>
            ) : (
              "—"
            ),
          },
          { label: "Expires", value: <span className="font-mono text-[12px] font-medium">{facts.expires}</span> },
        ]}
      />
      <TicketFoot
        note={
          stage === "active"
            ? "Sentinel enforces these boundaries for actions routed through it."
            : stage === "ready"
              ? replacesActive
                ? "Activating replaces the current task."
                : "Activating turns approval mode on for this task."
              : "Reads run freely; each write pauses for your approval."
        }
        actions={
          stage === "ready" && onActivate ? (
            <Button variant="raised" onClick={onActivate} disabled={activating}>
              {activating ? "Activating…" : "Activate task"}
            </Button>
          ) : undefined
        }
      />
    </Ticket>
  );
}

/** Modal receipt shown once after activation; the same ticket, blue, with the notches traced. */
export function ActivationReceipt({
  contract,
  onClose,
}: {
  contract: ContractRecord | null;
  onClose: () => void;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (contract && !dialog.open) dialog.showModal();
    if (!contract && dialog.open) dialog.close();
  }, [contract]);

  const objective = contract?.contract.objective ?? "";
  const operation = contract?.contract.allowed_operations[0] ?? "Not specified";
  const environment = contract?.contract.environment ?? "Not specified";
  const expires = contract?.expires_at ? `${formatMinutes(contract.expires_at)}` : "Not specified";

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby="activation-receipt-title"
      className="m-auto w-[min(92vw,680px)] max-w-none overflow-visible border-0 bg-transparent p-0 backdrop:bg-black/70"
      onClose={onClose}
    >
      {contract ? (
        <Ticket className="contract-receipt">
          <TicketHead
            eyebrow="Sentinel authorization"
            title="Contract active"
            titleId="activation-receipt-title"
            meta={objective}
            seal={<TicketSeal state="Active" />}
          />
          <TicketFacts
            items={[
              { label: "Operation", value: <span className="capitalize">{operation.replaceAll("_", " ")}</span> },
              { label: "Environment", value: <span className="capitalize">{environment}</span> },
              { label: "Expires", value: <span className="font-mono text-[12px] font-medium">{expires}</span> },
              {
                label: "Targets",
                value: (
                  <span className="flex flex-wrap gap-y-1">
                    {(contract.contract.exact_targets ?? []).map((target) => (
                      <Chip key={target}>{target}</Chip>
                    ))}
                  </span>
                ),
              },
            ]}
          />
          <TicketFoot
            note="Sentinel will enforce these boundaries for actions routed through it and ask before important changes."
            actions={
              <Button type="button" variant="raised" autoFocus onClick={onClose}>
                Done
              </Button>
            }
          />
        </Ticket>
      ) : null}
    </dialog>
  );
}

export function draftTitle(preview: ContractPreview | null): string {
  if (!preview?.operation || preview.targets.length === 0) return "Untitled task";
  const operation = preview.operation.charAt(0).toUpperCase() + preview.operation.slice(1);
  return `${operation.replaceAll("_", " ")} exactly ${preview.targets.join(", ")}.`;
}

function formatMinutes(iso: string) {
  const minutes = Math.round((new Date(iso).getTime() - Date.now()) / 60_000);
  if (minutes <= 0) return "Expired";
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest ? `${hours} h ${rest} min` : `${hours} h`;
}

function formatClock(value?: string) {
  if (!value) return "—";
  return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
