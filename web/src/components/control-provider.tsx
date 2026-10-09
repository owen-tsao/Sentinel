"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { useRouter } from "next/navigation";

import type {
  ContractRecord,
  ControlStatusResponse,
  PendingApprovalResponse,
  TaskProposalResponse,
} from "@/lib/control-types";
import {
  ControlApiError,
  approveAction,
  confirmProposal,
  controlRequest,
  getActiveAuthority,
  getControlStatus,
  getPendingProposal,
  listApprovals,
} from "@/lib/control-api";
import {
  listenForNotificationClicks,
  showPendingNotification,
  type NotificationClick,
  type PendingNotification,
} from "@/lib/notifications";

type ConnectionState =
  | "connecting"
  | "connected"
  | "pairing_required"
  | "expired"
  | "disconnected"
  | "error";

type ControlContextValue = {
  connection: ConnectionState;
  status: ControlStatusResponse | null;
  activeContract: ContractRecord | null;
  approvalCount: number;
  approvals: PendingApprovalResponse[];
  proposal: TaskProposalResponse | null;
  message: string;
  /** Set while a notification click is being carried out; the card shows the outcome. */
  notificationError: string | null;
  refresh: () => Promise<void>;
};

const ControlContext = createContext<ControlContextValue | null>(null);

function takePairingCapability(): string | null {
  const fragment = window.location.hash.slice(1);
  if (!fragment) return null;

  window.history.replaceState(
    null,
    "",
    `${window.location.pathname}${window.location.search}`,
  );
  try {
    if (fragment.includes("=")) {
      return new URLSearchParams(fragment).get("pair");
    }
    return decodeURIComponent(fragment);
  } catch {
    return null;
  }
}

export function ControlProvider({ children }: { children: ReactNode }) {
  const [connection, setConnection] =
    useState<ConnectionState>("connecting");
  const [status, setStatus] = useState<ControlStatusResponse | null>(null);
  const [activeContract, setActiveContract] =
    useState<ContractRecord | null>(null);
  const [approvals, setApprovals] = useState<PendingApprovalResponse[]>([]);
  const [proposal, setProposal] = useState<TaskProposalResponse | null>(null);
  const [message, setMessage] = useState("Connecting to local Sentinel…");
  // Remembered with the pending set it described, so it disappears as soon as
  // that set changes (the item was acted on, expired, or replaced).
  const [notificationError, setNotificationError] = useState<{ message: string; pendingKey: string } | null>(null);
  const hasConnected = useRef(false);
  const initialConnection = useRef<Promise<void> | null>(null);
  const router = useRouter();
  // Pending items already seen by this tab; seeded on the first successful
  // load so a reload does not re-announce what is already on screen.
  const seenPending = useRef<Set<string> | null>(null);
  const latest = useRef<{ contract: ContractRecord | null; proposal: TaskProposalResponse | null; approvals: PendingApprovalResponse[] }>({
    contract: null,
    proposal: null,
    approvals: [],
  });

  const refreshRef = useRef<() => Promise<void>>(async () => {});

  const handleClick = useCallback(
    async (click: NotificationClick) => {
      setNotificationError(null);
      const current = latest.current;
      if (click.action === "decide") {
        try {
          if (click.kind === "proposal") {
            // The click only names the draft; the stale-view guard still uses
            // whatever task this tab currently believes is active.
            if (current.proposal?.draft_id !== click.id) throw new Error("gone");
            await confirmProposal(click.id, {
              expected_active_task_id: current.contract?.task_id ?? null,
            });
          } else {
            if (!current.approvals.some((item) => item.approval_id === click.id)) throw new Error("gone");
            await approveAction(click.id, { typed_target: null });
          }
        } catch (error) {
          setNotificationError({
            message:
              error instanceof ControlApiError
                ? "The notification could not complete the decision; review it here."
                : "That item is no longer pending.",
            pendingKey: pendingKeyOf(current.proposal, current.approvals),
          });
        }
        await refreshRef.current();
      }
      router.push(click.path);
    },
    [router],
  );

  const announceNewPending = useCallback(
    (nextProposal: TaskProposalResponse | null, nextApprovals: PendingApprovalResponse[]) => {
      const ids = new Set<string>();
      if (nextProposal) ids.add(`proposal:${nextProposal.draft_id}`);
      for (const item of nextApprovals) ids.add(`approval:${item.approval_id}`);
      const seen = seenPending.current;
      seenPending.current = ids;
      if (seen === null) return;
      if (typeof document !== "undefined" && document.hasFocus()) return;
      if (nextProposal && !seen.has(`proposal:${nextProposal.draft_id}`)) {
        void showPendingNotification(proposalNotification(nextProposal), handleClick);
      }
      for (const item of nextApprovals) {
        if (!seen.has(`approval:${item.approval_id}`)) {
          void showPendingNotification(approvalNotification(item), handleClick);
        }
      }
    },
    [handleClick],
  );

  const refresh = useCallback(async () => {
    try {
      const nextStatus = await getControlStatus();
      const [authority, approvals, proposals] = await Promise.all([
        getActiveAuthority(),
        listApprovals(),
        getPendingProposal(),
      ]);
      hasConnected.current = true;
      const nextContract = authority.active_contract ?? null;
      const nextProposal = proposals.proposal ?? null;
      const nextApprovals = approvals.approvals;
      latest.current = { contract: nextContract, proposal: nextProposal, approvals: nextApprovals };
      const pendingKey = pendingKeyOf(nextProposal, nextApprovals);
      setNotificationError((current) => (current && current.pendingKey !== pendingKey ? null : current));
      setStatus(nextStatus);
      setActiveContract(nextContract);
      setApprovals(nextApprovals);
      setProposal(nextProposal);
      setConnection("connected");
      setMessage("Sentinel-owned local control channel");
      announceNewPending(nextProposal, nextApprovals);
    } catch (error) {
      setStatus(null);
      setActiveContract(null);
      setApprovals([]);
      setProposal(null);
      if (error instanceof ControlApiError && error.status === 401) {
        setConnection(hasConnected.current ? "expired" : "pairing_required");
        setMessage(
          hasConnected.current
            ? "Control session expired"
            : "Open a fresh Sentinel pairing link",
        );
      } else if (error instanceof TypeError) {
        setConnection("disconnected");
        setMessage("Local FastAPI backend is unreachable");
      } else {
        setConnection("error");
        setMessage("Control state could not be loaded");
      }
    }
  }, [announceNewPending]);

  useEffect(() => {
    refreshRef.current = refresh;
  }, [refresh]);

  useEffect(() => listenForNotificationClicks(handleClick), [handleClick]);

  useEffect(() => {
    if (initialConnection.current === null) {
      const capability = takePairingCapability();
      initialConnection.current = (async () => {
        if (capability) {
          try {
            await controlRequest("/control/pair/exchange", {
              method: "POST",
              body: JSON.stringify({ capability }),
            });
          } catch (error) {
            setConnection(
              error instanceof TypeError ? "disconnected" : "pairing_required",
            );
            setMessage(
              error instanceof TypeError
                ? "Local FastAPI backend is unreachable"
                : "Pairing link is invalid, expired, or already used",
            );
            return;
          }
        }
        await refresh();
      })();
    }

    void initialConnection.current;
    const interval = window.setInterval(() => {
      void refresh();
    }, 15_000);
    return () => {
      window.clearInterval(interval);
    };
  }, [refresh]);

  const value = useMemo(
    () => ({
      connection,
      status,
      activeContract,
      approvalCount: approvals.length,
      approvals,
      proposal,
      message,
      notificationError: notificationError?.message ?? null,
      refresh,
    }),
    [connection, status, activeContract, approvals, proposal, message, notificationError, refresh],
  );

  return (
    <ControlContext.Provider value={value}>{children}</ControlContext.Provider>
  );
}

function pendingKeyOf(proposal: TaskProposalResponse | null, approvals: PendingApprovalResponse[]): string {
  return [proposal ? `proposal:${proposal.draft_id}` : "", ...approvals.map((item) => `approval:${item.approval_id}`)].join("|");
}

/** The body names the exact grant so a mis-click cannot approve something vague. */
function proposalNotification(proposal: TaskProposalResponse): PendingNotification {
  const grant = [
    proposal.operation === "write" ? "read and add notes" : "read only",
    proposal.exact_targets.join(", "),
    `${proposal.task_duration_minutes} min`,
  ].join(" · ");
  return {
    kind: "proposal",
    id: proposal.draft_id,
    title: "Your agent proposed a task",
    body: `${proposal.objective}\n${grant}`,
    decideLabel: "Activate",
    path: "/",
  };
}

function approvalNotification(approval: PendingApprovalResponse): PendingNotification {
  const needsTyped = approval.operation === "delete" || approval.environment === "production";
  const what =
    approval.tool === "sentinel_issue_add_note"
      ? `Add a note to ${approval.targets.join(", ")}`
      : `${approval.operation} · ${approval.targets.join(", ") || approval.raw_command}`;
  return {
    kind: "approval",
    id: approval.approval_id,
    title: "A write is waiting for your approval",
    body: what,
    decideLabel: needsTyped ? undefined : "Approve",
    path: "/approvals",
  };
}

export function useControl() {
  const value = useContext(ControlContext);
  if (!value) {
    throw new Error("useControl must be used inside ControlProvider");
  }
  return value;
}
