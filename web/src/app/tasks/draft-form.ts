import type {
  AcceptedContractDraft,
  DraftSuggestionResponse,
} from "@/lib/control-types";

/**
 * Form state for the task contract. `allowed_effects` is not a field: the
 * server derives it as exactly the chosen operation, so the form does too.
 * Letting people type it only produced contradictions ("read" operation with
 * "write" effects) that the server then rejected.
 */
export type DraftForm = {
  operation: string;
  exactTargets: string[];
  environment: string;
  expectedSideEffects: string;
  forbiddenOperations: string;
  forbiddenEffects: string;
  forbiddenEffectCodes: string;
  rollbackPlan: string;
  dryRunRequired: "" | "yes" | "no";
  rollbackRequired: boolean;
  transactionRequired: boolean;
  backupRequired: boolean;
  expiresInMinutes: string;
  toolFamily: "shell" | "sentinel_issue_fixture";
};

export const emptyForm: DraftForm = {
  operation: "",
  exactTargets: [],
  environment: "",
  expectedSideEffects: "",
  forbiddenOperations: "",
  forbiddenEffects: "",
  forbiddenEffectCodes: "",
  rollbackPlan: "",
  dryRunRequired: "",
  rollbackRequired: false,
  transactionRequired: false,
  backupRequired: false,
  expiresInMinutes: "60",
  toolFamily: "shell",
};

export const OPERATIONS = [
  "read",
  "write",
  "delete",
  "execute",
  "network",
  "external_communication",
  "credential_access",
] as const;

export const ENVIRONMENTS = ["sandbox", "dev", "staging", "production"] as const;

export function formFromSuggestions(
  suggestions: DraftSuggestionResponse[],
  fixedEnvironment: string | null,
): DraftForm {
  const values = new Map(suggestions.map((item) => [item.field, item.value]));
  return {
    operation: stringValue(values.get("operation")),
    exactTargets: listValue(values.get("exact_targets")),
    environment: fixedEnvironment ?? stringValue(values.get("environment")),
    expectedSideEffects: linesValue(values.get("expected_side_effects")),
    forbiddenOperations: commaValue(values.get("forbidden_operations")),
    forbiddenEffects: linesValue(values.get("forbidden_effects")),
    forbiddenEffectCodes: commaValue(values.get("forbidden_effect_codes")),
    rollbackPlan: stringValue(values.get("rollback_plan")),
    dryRunRequired:
      typeof values.get("dry_run_required") === "boolean"
        ? values.get("dry_run_required") === true
          ? "yes"
          : "no"
        : "",
    rollbackRequired: values.get("rollback_required") === true,
    transactionRequired: values.get("transaction_required") === true,
    backupRequired: values.get("backup_required") === true,
    expiresInMinutes: stringValue(values.get("expires_in_minutes")) || "60",
    toolFamily: "shell",
  };
}

export function formFromAccepted(accepted: AcceptedContractDraft): DraftForm {
  return {
    operation: accepted.operation,
    exactTargets: [...accepted.exact_targets],
    environment: accepted.environment,
    expectedSideEffects: accepted.expected_side_effects.join("\n"),
    forbiddenOperations: (accepted.forbidden_operations ?? []).join(", "),
    forbiddenEffects: accepted.forbidden_effects.join("\n"),
    forbiddenEffectCodes: (accepted.forbidden_effect_codes ?? []).join(", "),
    rollbackPlan: accepted.rollback_plan,
    dryRunRequired: accepted.dry_run_required ? "yes" : "no",
    rollbackRequired: accepted.rollback_required ?? false,
    transactionRequired: accepted.transaction_required ?? false,
    backupRequired: accepted.backup_required ?? false,
    expiresInMinutes: String(accepted.expires_in_minutes ?? 60),
    toolFamily: accepted.tool_family ?? "shell",
  };
}

/** Null until every required answer is present; the server validates again on save. */
export function acceptedContract(form: DraftForm): AcceptedContractDraft | null {
  const expectedEffects = nonemptyLines(form.expectedSideEffects);
  const forbiddenEffects = nonemptyLines(form.forbiddenEffects);
  const expiry = Number(form.expiresInMinutes);
  if (
    !form.operation ||
    !form.environment ||
    form.exactTargets.length === 0 ||
    expectedEffects.length === 0 ||
    forbiddenEffects.length === 0 ||
    !form.rollbackPlan.trim() ||
    !form.dryRunRequired ||
    !Number.isInteger(expiry) ||
    expiry < 1 ||
    expiry > 1440
  ) {
    return null;
  }
  return {
    operation: form.operation as AcceptedContractDraft["operation"],
    exact_targets: form.exactTargets,
    environment: form.environment as AcceptedContractDraft["environment"],
    expected_side_effects: expectedEffects,
    allowed_effects: [form.operation],
    forbidden_operations: commaList(
      form.forbiddenOperations,
    ) as AcceptedContractDraft["forbidden_operations"],
    forbidden_effects: forbiddenEffects,
    forbidden_effect_codes: commaList(form.forbiddenEffectCodes),
    rollback_plan: form.rollbackPlan.trim(),
    dry_run_required: form.dryRunRequired === "yes",
    rollback_required: form.rollbackRequired,
    transaction_required: form.transactionRequired,
    backup_required: form.backupRequired,
    expires_in_minutes: expiry,
    tool_family: form.toolFamily,
  };
}

export function suggestionSourceLabel(source: DraftSuggestionResponse["source"]) {
  return source === "safe_default"
    ? "Safe default"
    : source === "prompt_explicit"
      ? "From your task"
      : "Suggested";
}

function nonemptyLines(value: string) {
  return value
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean);
}

function commaList(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function stringValue(value: unknown) {
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

function listValue(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string") : [];
}

function linesValue(value: unknown) {
  return Array.isArray(value)
    ? value.filter((item) => typeof item === "string").join("\n")
    : stringValue(value);
}

function commaValue(value: unknown) {
  return Array.isArray(value)
    ? value.filter((item) => typeof item === "string").join(", ")
    : stringValue(value);
}
