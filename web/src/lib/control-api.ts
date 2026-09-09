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
} from "@/lib/control-types";

const API_ORIGIN =
  process.env.NEXT_PUBLIC_SENTINEL_API_ORIGIN ?? "http://127.0.0.1:8000";

export class ControlApiError extends Error {
  constructor(readonly status: number) {
    super(`Control API returned ${status}`);
  }
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
    throw new ControlApiError(response.status);
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
