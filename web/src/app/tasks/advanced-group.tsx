"use client";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { DraftSuggestionResponse } from "@/lib/control-types";

import { Field } from "./field";
import { suggestionSourceLabel, type DraftForm } from "./draft-form";

/**
 * Rarely-changed defaults: the forbidden lists, the fixed tool/scope facts,
 * shell safeguards, and the raw JSON. Collapsed by default; the safe defaults
 * are accepted unless the user changes them.
 */
export function AdvancedGroup({
  form,
  update,
  sources,
  fixture,
  json,
}: {
  form: DraftForm;
  update: (patch: Partial<DraftForm>) => void;
  sources: Map<string, DraftSuggestionResponse>;
  fixture: boolean;
  json: unknown;
}) {
  return (
    <details className="group border-t border-[var(--line)]">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-5 py-3.5 outline-none hover:bg-[var(--hover)] focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-inset">
        <span>
          <span className="block text-[14px] font-semibold tracking-[-0.01em]">Advanced</span>
          <span className="mt-0.5 block text-[12px] text-[var(--subtext)]">
            Forbidden actions, safeguards, and the raw contract. Safe defaults apply unless changed.
          </span>
        </span>
        <span aria-hidden="true" className="text-[12px] text-[var(--subtext)] group-open:hidden">
          Show
        </span>
        <span aria-hidden="true" className="hidden text-[12px] text-[var(--subtext)] group-open:inline">
          Hide
        </span>
      </summary>
      <div className="flex flex-col gap-4 px-5 pb-5">
        <Field
          label="Forbidden operations"
          htmlFor="contract-forbidden-operations"
          source={sources.get("forbidden_operations")}
          hint="Comma-separated. The agent is refused these outright."
        >
          <Input
            id="contract-forbidden-operations"
            value={form.forbiddenOperations}
            onChange={(event) => update({ forbiddenOperations: event.target.value })}
            className="font-mono text-[12px]"
          />
        </Field>
        <Field
          label="Forbidden effects"
          htmlFor="contract-forbidden-effects"
          source={sources.get("forbidden_effects")}
        >
          <Textarea
            id="contract-forbidden-effects"
            value={form.forbiddenEffects}
            onChange={(event) => update({ forbiddenEffects: event.target.value })}
            className="min-h-16"
          />
        </Field>
        <Field
          label="Forbidden effect codes"
          htmlFor="contract-forbidden-effect-codes"
          source={sources.get("forbidden_effect_codes")}
        >
          <Input
            id="contract-forbidden-effect-codes"
            value={form.forbiddenEffectCodes}
            onChange={(event) => update({ forbiddenEffectCodes: event.target.value })}
            className="font-mono text-[12px]"
          />
        </Field>

        <dl className="grid gap-x-6 gap-y-2 text-[13px] sm:grid-cols-[120px_minmax(0,1fr)]">
          <dt className="text-[var(--subtext)]">Tool</dt>
          <dd className="flex items-center gap-2 font-mono text-[12px]">
            {fixture ? "sentinel_issue_fixture" : "shell only"}
            {sources.has("allowed_tools") ? (
              <Badge variant="secondary">{suggestionSourceLabel(sources.get("allowed_tools")!.source)}</Badge>
            ) : null}
          </dd>
          <dt className="text-[var(--subtext)]">Maximum scope</dt>
          <dd className="flex items-center gap-2 font-mono text-[12px]">
            exact
            {sources.has("maximum_scope") ? (
              <Badge variant="secondary">{suggestionSourceLabel(sources.get("maximum_scope")!.source)}</Badge>
            ) : null}
          </dd>
          <dt className="text-[var(--subtext)]">Allowed changes</dt>
          <dd className="font-mono text-[12px]">
            {form.operation ? form.operation : "—"}
            <span className="ml-2 font-sans text-[11px] text-[var(--faint)]">always the chosen operation</span>
          </dd>
        </dl>

        {!fixture ? (
          <fieldset className="border-0 p-0">
            <legend className="text-[12px] font-medium">Required safeguards</legend>
            <div className="mt-2 grid gap-2 sm:grid-cols-3">
              {(
                [
                  ["rollbackRequired", "Rollback", "rollback_required"],
                  ["transactionRequired", "Transaction", "transaction_required"],
                  ["backupRequired", "Backup", "backup_required"],
                ] as const
              ).map(([key, label, field]) => (
                <label
                  key={key}
                  htmlFor={`contract-safeguard-${key}`}
                  className="flex h-9 cursor-pointer items-center gap-2.5 rounded-[var(--radius-control)] border-[1.5px] border-[var(--outline)] bg-white px-3 text-[13px]"
                >
                  <input
                    id={`contract-safeguard-${key}`}
                    type="checkbox"
                    className="size-3.5 accent-black"
                    checked={Boolean(form[key])}
                    onChange={(event) => update({ [key]: event.target.checked } as Partial<DraftForm>)}
                  />
                  {label}
                  {sources.has(field) ? (
                    <Badge variant="secondary" className="ml-auto">
                      {suggestionSourceLabel(sources.get(field)!.source)}
                    </Badge>
                  ) : null}
                </label>
              ))}
            </div>
          </fieldset>
        ) : null}

        {json ? (
          <details className="border-t border-[var(--line)] pt-3">
            <summary className="w-fit cursor-pointer text-[12px] font-medium outline-none focus-visible:ring-2 focus-visible:ring-black">
              Raw contract JSON
            </summary>
            <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-[var(--radius-control)] border-[1.5px] border-[var(--outline)] bg-[var(--canvas)] p-4 font-mono text-[11px] leading-5">
              {JSON.stringify(json, null, 2)}
            </pre>
          </details>
        ) : null}
      </div>
    </details>
  );
}
