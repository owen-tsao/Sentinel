import type { AuditEvent } from "@/lib/control-types";

/** Human labels for audit rows, shared by the Overview ledger and the Activity page. */
export function eventLabel(eventType: string) {
  return {
    authority_transition_prepared: "Task update prepared",
    authority_transition_completed: "Task settings updated",
    task_proposed: "Agent proposed a task",
    task_proposal_confirmed: "You activated a proposed task",
    task_proposal_dismissed: "Proposed task dismissed",
    task_proposal_superseded: "Proposed task replaced",
    task_proposal_expired: "Proposed task expired",
    pre_decision: "Change reviewed",
    decision: "Safety decision made",
    exact_action_approved: "You approved a change",
    exact_action_denied: "You denied a change",
    execution_admitted: "Approved change started",
    post_execution: "Change completed",
  }[eventType] ?? "Workspace activity";
}

export function verdictLabel(verdict: NonNullable<AuditEvent["verdict"]>) {
  return {
    allow: "Allowed",
    warn: "Warning",
    confirm_required: "Asked for approval",
    block: "Blocked",
  }[verdict];
}

/** Tool name and single target for MCP-mediated events, or null for other events. */
export function eventTool(event: AuditEvent): { tool: string; target: string | null } | null {
  const details = event.details ?? {};
  const tool = details.tool;
  if (typeof tool !== "string") return null;
  const targets = Array.isArray(details.targets) ? details.targets.map(String) : [];
  return { tool, target: targets.length === 1 ? targets[0] : targets.length ? `${targets.length} targets` : null };
}
