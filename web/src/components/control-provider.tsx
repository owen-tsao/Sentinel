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

import type {
  ContractRecord,
  ControlStatusResponse,
  TaskProposalResponse,
} from "@/lib/control-types";
import {
  ControlApiError,
  controlRequest,
  getActiveAuthority,
  getControlStatus,
  getPendingProposal,
  listApprovals,
} from "@/lib/control-api";

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
  proposal: TaskProposalResponse | null;
  message: string;
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
  const [approvalCount, setApprovalCount] = useState(0);
  const [proposal, setProposal] = useState<TaskProposalResponse | null>(null);
  const [message, setMessage] = useState("Connecting to local Sentinel…");
  const hasConnected = useRef(false);
  const initialConnection = useRef<Promise<void> | null>(null);

  const refresh = useCallback(async () => {
    try {
      const nextStatus = await getControlStatus();
      const [authority, approvals, proposals] = await Promise.all([
        getActiveAuthority(),
        listApprovals(),
        getPendingProposal(),
      ]);
      hasConnected.current = true;
      setStatus(nextStatus);
      setActiveContract(authority.active_contract ?? null);
      setApprovalCount(approvals.approvals.length);
      setProposal(proposals.proposal ?? null);
      setConnection("connected");
      setMessage("Sentinel-owned local control channel");
    } catch (error) {
      setStatus(null);
      setActiveContract(null);
      setApprovalCount(0);
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
  }, []);

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
      approvalCount,
      proposal,
      message,
      refresh,
    }),
    [connection, status, activeContract, approvalCount, proposal, message, refresh],
  );

  return (
    <ControlContext.Provider value={value}>{children}</ControlContext.Provider>
  );
}

export function useControl() {
  const value = useContext(ControlContext);
  if (!value) {
    throw new Error("useControl must be used inside ControlProvider");
  }
  return value;
}
