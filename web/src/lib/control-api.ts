import type {
  ActiveAuthorityResponse,
  ApprovalActionResponse,
  ApprovalDecisionRequest,
  ApprovalListResponse,
  AuditListResponse,
  ContractActivationRequest,
  ContractActivationResponse,
  ContractDraftRequest,
  ContractDraftResponse,
  ControlStatusResponse,
  PendingProposalResponse,
  ProposalAdjustResponse,
  ProposalConfirmRequest,
  ProposalConfirmResponse,
  ProposalDismissResponse,
  TargetSuggestionsResponse,
} from "@/lib/control-types";

export const API_ORIGIN =
  process.env.NEXT_PUBLIC_SENTINEL_API_ORIGIN ?? "http://127.0.0.1:8000";

/** Host shown in the sidebar footer so it is obvious which local process the UI talks to. */
export const API_HOST = API_ORIGIN.replace(/^https?:\/\//, "");

export class ControlApiError extends Error {
  constructor(
    readonly status: number,
    /** Human-readable reason from the server's `detail`, when it sent one. */
    readonly detail: string | null = null,
  ) {
    super(`Control API returned ${status}`);
  }
}

/** FastAPI puts the reason in `detail`, either as a string or as `{ message }`. */
async function readErrorDetail(response: Response): Promise<string | null> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    const detail = body?.detail;
    if (typeof detail === "string") return detail;
    if (detail && typeof detail === "object" && "message" in detail) {
      const message = (detail as { message?: unknown }).message;
      return typeof message === "string" ? message : null;
    }
  } catch {
    // Non-JSON error body; the status code is all we have.
  }
  return null;
}

export async function controlRequest<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`${API_ORIGIN}${path}`, {
    ...init,
    cache: "no-store",
    credentials: "include",
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    throw new ControlApiError(response.status, await readErrorDetail(response));
  }
  return (await response.json()) as T;
}

export function getControlStatus() {
  return controlRequest<ControlStatusResponse>("/control/status");
}

export function getActiveAuthority() {
  return controlRequest<ActiveAuthorityResponse>("/control/authority/active");
}

export function listApprovals() {
  return controlRequest<ApprovalListResponse>("/control/approvals");
}

export function draftContract(payload: ContractDraftRequest) {
  return controlRequest<ContractDraftResponse>("/control/contracts/draft", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/** Workspace paths and fixture issue IDs offered by the task form's target picker. */
export function getTargetSuggestions() {
  return controlRequest<TargetSuggestionsResponse>("/control/targets");
}

export function activateContract(payload: ContractActivationRequest) {
  return controlRequest<ContractActivationResponse>(
    "/control/contracts/activate",
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
  );
}

export function approveAction(
  approvalId: string,
  payload?: ApprovalDecisionRequest,
) {
  return controlRequest<ApprovalActionResponse>(
    `/control/approvals/${encodeURIComponent(approvalId)}/approve`,
    {
      method: "POST",
      body: JSON.stringify(payload ?? {}),
    },
  );
}

export function denyAction(approvalId: string) {
  return controlRequest<ApprovalActionResponse>(
    `/control/approvals/${encodeURIComponent(approvalId)}/deny`,
    { method: "POST" },
  );
}

export function getPendingProposal() {
  return controlRequest<PendingProposalResponse>("/control/proposals/pending");
}

/**
 * The body carries only a stale-view guard: the task ID the browser saw, or
 * null if it saw none. Every authority fact the task will grant is re-read
 * server-side from the stored draft named by `draftId`.
 */
export function confirmProposal(
  draftId: string,
  payload: ProposalConfirmRequest,
) {
  return controlRequest<ProposalConfirmResponse>(
    `/control/proposals/${encodeURIComponent(draftId)}/confirm`,
    { method: "POST", body: JSON.stringify(payload) },
  );
}

export function dismissProposal(draftId: string) {
  return controlRequest<ProposalDismissResponse>(
    `/control/proposals/${encodeURIComponent(draftId)}/dismiss`,
    { method: "POST" },
  );
}

export function adjustProposal(draftId: string) {
  return controlRequest<ProposalAdjustResponse>(
    `/control/proposals/${encodeURIComponent(draftId)}/adjust`,
    { method: "POST" },
  );
}

/** Session-only handoff from the compact card to the full form. Not authority. */
export const PROPOSAL_PREFILL_KEY = "sentinel.proposal-prefill";

export type AuditFilters = {
  taskId?: string;
  eventType?: string;
  verdict?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
};

export function getAuditEvents(filters: AuditFilters = {}) {
  const query = new URLSearchParams();
  if (filters.taskId) query.set("task_id", filters.taskId);
  if (filters.eventType) query.set("event_type", filters.eventType);
  if (filters.verdict) query.set("verdict", filters.verdict);
  if (filters.startTime) query.set("start_time", filters.startTime);
  if (filters.endTime) query.set("end_time", filters.endTime);
  query.set("limit", String(filters.limit ?? 200));
  return controlRequest<AuditListResponse>(`/control/audit?${query}`);
}
