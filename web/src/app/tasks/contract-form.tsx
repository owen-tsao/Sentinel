"use client";

import type { Dispatch, ReactNode, SetStateAction } from "react";

import { TargetPicker } from "@/components/target-picker";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import type {
  AcceptedContractDraft,
  ContractDraftResponse,
  IntegrationStatusResponse,
  TargetSuggestionsResponse,
} from "@/lib/control-types";

import { AdvancedGroup } from "./advanced-group";
import { Field } from "./field";
import { ENVIRONMENTS, OPERATIONS, type DraftForm } from "./draft-form";

export {
  acceptedContract,
  emptyForm,
  formFromAccepted,
  formFromSuggestions,
  type DraftForm,
} from "./draft-form";

type SetForm = Dispatch<SetStateAction<DraftForm>>;

/**
 * The grouped settings under the goal. Two groups are always open (what the
 * agent may do; safety and recovery); the rarely-touched defaults sit under
 * "Advanced". Fields the server could not infer are marked "Needs your answer".
 */
export function ContractForm({
  form,
  setForm,
  preview,
  locked,
  fixedEnvironment,
  integration,
  suggestions,
  operationForbidden,
  accepted,
}: {
  form: DraftForm;
  setForm: SetForm;
  preview: ContractDraftResponse;
  locked: boolean;
  fixedEnvironment: string | null;
  integration: IntegrationStatusResponse | null;
  suggestions: TargetSuggestionsResponse | null;
  operationForbidden: boolean;
  accepted: AcceptedContractDraft | null;
}) {
  const sources = new Map(
    preview.suggestions.map((item) => [item.field, item]),
  );
  const questions = new Map(
    preview.questions.map((item) => [item.field, item.prompt]),
  );
  const fixture = form.toolFamily === "sentinel_issue_fixture";
  const targetOptions = fixture
    ? (suggestions?.fixture_issues ?? [])
    : (suggestions?.paths ?? []).map((item) => item.path);
  const update = (patch: Partial<DraftForm>) =>
    setForm((current) => ({ ...current, ...patch }));
  const workspaceRoot = suggestions?.workspace_root ?? "/workspace";
  // A relative path is almost always meant inside the workspace; the server
  // would reject it as written, so canonicalise it here and show the result.
  const normalizeTarget = (value: string) =>
    fixture || !value || value.startsWith("/")
      ? value
      : `${workspaceRoot}/${value.replace(/^\.?\//, "")}`;
  // Mark a field only while it is still empty; once answered the marker goes
  // away so the remaining blockers stand out.
  const needsAnswer = (field: string, empty: boolean) =>
    empty
      ? (questions.get(field) ?? "Required before you can confirm.")
      : undefined;

  return (
    <fieldset
      disabled={locked}
      className="min-w-0 border-0 p-0 disabled:opacity-70"
    >
      <legend className="sr-only">Contract settings</legend>

      <Group
        title="What the agent may do"
        description="These four settings decide the boundary Sentinel enforces."
      >
        <div className="grid gap-4 sm:grid-cols-3">
          <Field
            label="Operation"
            htmlFor="contract-operation"
            source={sources.get("operation")}
            question={needsAnswer("operation", !form.operation)}
            problem={
              operationForbidden
                ? "This operation is in the forbidden list under Advanced. Remove it there to allow it."
                : undefined
            }
          >
            <Select
              value={form.operation}
              onValueChange={(value) => update({ operation: value })}
            >
              <SelectTrigger id="contract-operation">
                <SelectValue placeholder="Choose one" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {(fixture ? ["read", "write"] : OPERATIONS).map((value) => (
                    <SelectItem key={value} value={value}>
                      <span className="capitalize">
                        {value.replaceAll("_", " ")}
                      </span>
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
          </Field>

          <Field
            label="Environment"
            htmlFor="contract-environment"
            source={fixedEnvironment ? undefined : sources.get("environment")}
            question={
              fixedEnvironment ? undefined : questions.get("environment")
            }
          >
            {fixedEnvironment ? (
              <Input
                id="contract-environment"
                readOnly
                value={fixedEnvironment}
                className="capitalize"
                aria-describedby="contract-environment-hint"
              />
            ) : (
              <Select
                value={form.environment}
                onValueChange={(value) => update({ environment: value })}
              >
                <SelectTrigger id="contract-environment">
                  <SelectValue placeholder="Choose one" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {ENVIRONMENTS.map((value) => (
                      <SelectItem key={value} value={value}>
                        <span className="capitalize">{value}</span>
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            )}
          </Field>
          <Field
            label="Expires in minutes"
            htmlFor="contract-expires-in-minutes"
          >
            <Input
              id="contract-expires-in-minutes"
              type="number"
              min={1}
              max={1440}
              value={form.expiresInMinutes}
              onChange={(event) =>
                update({ expiresInMinutes: event.target.value })
              }
            />
          </Field>
        </div>

        <Field
          label={fixture ? "Allowed fixture issues" : "Allowed locations"}
          htmlFor="contract-exact-targets"
          source={sources.get("exact_targets")}
          question={needsAnswer(
            "exact_targets",
            form.exactTargets.length === 0,
          )}
          trailing={
            integration ? (
              <TargetKindSelect form={form} update={update} />
            ) : undefined
          }
          hint={
            fixture
              ? "Reads are always included. Writes add one reviewed note per approval."
              : `Exact paths under ${workspaceRoot}. Pick from the list or type one; relative paths are placed under it.`
          }
        >
          <TargetPicker
            id="contract-exact-targets"
            values={form.exactTargets}
            onChange={(next) => update({ exactTargets: next })}
            suggestions={targetOptions}
            normalize={normalizeTarget}
            disabled={locked}
            placeholder={
              fixture
                ? "Type an issue ID, e.g. SPIKE-1"
                : "Type or pick a path, e.g. /workspace/api.py"
            }
            emptyHint={
              targetOptions.length === 0
                ? "No suggestions available; type the exact path."
                : "No matches; press Enter to add what you typed."
            }
          />
        </Field>
      </Group>

      <Group
        title="Safety and recovery"
        description="What should happen, and what to do if it goes wrong."
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            label="Expected outcome"
            htmlFor="contract-expected-side-effects"
            source={sources.get("expected_side_effects")}
            question={needsAnswer(
              "expected_side_effects",
              !form.expectedSideEffects.trim(),
            )}
          >
            <Textarea
              id="contract-expected-side-effects"
              value={form.expectedSideEffects}
              onChange={(event) =>
                update({ expectedSideEffects: event.target.value })
              }
              placeholder="One expected change per line."
              className="min-h-16"
            />
          </Field>

          <Field
            label="If something goes wrong"
            htmlFor="contract-rollback-plan"
            source={sources.get("rollback_plan")}
            question={needsAnswer("rollback_plan", !form.rollbackPlan.trim())}
          >
            <Textarea
              id="contract-rollback-plan"
              value={form.rollbackPlan}
              onChange={(event) => update({ rollbackPlan: event.target.value })}
              placeholder="How this exact change is undone."
              className="min-h-16"
            />
          </Field>
        </div>

        {!fixture ? (
          <Field
            label="Run a dry run first"
            htmlFor="contract-dry-run-required"
            source={sources.get("dry_run_required")}
            question={needsAnswer("dry_run_required", !form.dryRunRequired)}
          >
            <Select
              value={form.dryRunRequired}
              onValueChange={(value) =>
                update({ dryRunRequired: value as "yes" | "no" })
              }
            >
              <SelectTrigger id="contract-dry-run-required">
                <SelectValue placeholder="Choose one" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="yes">
                    Yes — the agent must preview shell changes before applying
                    them
                  </SelectItem>
                  <SelectItem value="no">
                    No — apply directly after the other checks
                  </SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </Field>
        ) : null}
      </Group>

      <AdvancedGroup
        form={form}
        update={update}
        sources={sources}
        fixture={fixture}
        json={preview.proposed_contract?.contract ?? accepted}
      />
    </fieldset>
  );
}

function TargetKindSelect({
  form,
  update,
}: {
  form: DraftForm;
  update: (patch: Partial<DraftForm>) => void;
}) {
  return (
    <Select
      value={form.toolFamily}
      onValueChange={(value) => {
        const toolFamily = value as DraftForm["toolFamily"];
        const fixture = toolFamily === "sentinel_issue_fixture";
        update({
          toolFamily,
          exactTargets: [],
          // Fixture tools have no dry-run, rollback, transaction, or backup
          // mode; leaving any of these on would make every real call fail closed.
          dryRunRequired: fixture ? "no" : form.dryRunRequired,
          rollbackRequired: fixture ? false : form.rollbackRequired,
          transactionRequired: fixture ? false : form.transactionRequired,
          backupRequired: fixture ? false : form.backupRequired,
          operation:
            fixture && !["read", "write"].includes(form.operation)
              ? ""
              : form.operation,
        });
      }}
    >
      <SelectTrigger
        id="contract-tool-family"
        aria-label="Target kind"
        className="h-7 w-auto min-w-[200px] text-[12px]"
      >
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectGroup>
          <SelectItem value="shell">Workspace files (shell)</SelectItem>
          <SelectItem value="sentinel_issue_fixture">
            Fixture issues (Cursor MCP)
          </SelectItem>
        </SelectGroup>
      </SelectContent>
    </Select>
  );
}

/** Title → one line → fields, separated from the next group by a hairline. */
function Group({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <section className="border-t border-[var(--line)] px-5 py-4">
      <h2 className="text-[14px] font-semibold tracking-[-0.01em]">{title}</h2>
      <p className="mt-0.5 text-[12px] text-[var(--subtext)]">{description}</p>
      <div className="mt-4 flex flex-col gap-4">{children}</div>
    </section>
  );
}
