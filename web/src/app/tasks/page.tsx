"use client";

import { ArrowUpRight, Check, CircleAlert, FileCheck2 } from "lucide-react";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";

import { useControl } from "@/components/control-provider";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import {
  activateContract,
  ControlApiError,
  draftContract,
} from "@/lib/control-api";
import type {
  AcceptedContractDraft,
  ContractRecord,
  ContractDraftResponse,
  DraftSuggestionResponse,
} from "@/lib/control-types";

/**
 * Suggested settings that decide what the agent is allowed to do. These must be
 * explicitly confirmed. Every other suggestion either describes the task or
 * only narrows it, so accepting it unchanged cannot widen the boundary.
 */
const AUTHORITY_FIELDS = new Set([
  "operation",
  "exact_targets",
  "environment",
  "allowed_effects",
  "expires_in_minutes",
]);

type DraftForm = {
  operation: string;
  exactTargets: string;
  environment: string;
  expectedSideEffects: string;
  allowedEffects: string;
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

const emptyForm: DraftForm = {
  operation: "",
  exactTargets: "",
  environment: "",
  expectedSideEffects: "",
  allowedEffects: "",
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

export default function TasksPage() {
  const { activeContract, refresh, status } = useControl();
  const integration = status?.integration ?? null;
  const [rawPrompt, setRawPrompt] = useState("");
  const [preview, setPreview] = useState<ContractDraftResponse | null>(null);
  const [form, setForm] = useState<DraftForm>(emptyForm);
  const [reviewed, setReviewed] = useState<Set<string>>(new Set());
  const [safetyOpen, setSafetyOpen] = useState(false);
  const [goalEditing, setGoalEditing] = useState(false);
  const [receiptContract, setReceiptContract] = useState<ContractRecord | null>(
    null,
  );
  const editGoalRef = useRef<HTMLButtonElement>(null);
  const [pending, setPending] = useState<"compile" | "propose" | "activate" | null>(
    null,
  );
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const sources = useMemo(
    () =>
      new Map(
        (preview?.suggestions ?? []).map((suggestion) => [
          suggestion.field,
          suggestion,
        ]),
      ),
    [preview],
  );
  const accepted = useMemo(() => acceptedContract(form), [form]);
  const allSuggestedReviewed =
    preview?.suggestions
      .filter((item) => AUTHORITY_FIELDS.has(item.field))
      .every((item) => reviewed.has(item.field)) ?? false;
  const canPropose =
    preview !== null &&
    accepted !== null &&
    allSuggestedReviewed &&
    !preview.proposed_contract;
  const proposedIsActive =
    preview?.proposed_contract !== undefined &&
    activeContract !== null &&
    preview?.proposed_contract?.contract_id === activeContract?.contract_id &&
    preview?.proposed_contract?.version === activeContract?.version;

  async function compile(event: FormEvent) {
    event.preventDefault();
    if (new TextEncoder().encode(rawPrompt).length > 32_000) {
      setError("Task goal must be 32,000 bytes or fewer.");
      setNotice(null);
      return;
    }
    setPending("compile");
    setError(null);
    setNotice(null);
    try {
      const result = await draftContract({ raw_prompt: rawPrompt });
      setPreview(result);
      setForm(formFromSuggestions(result.suggestions));
      setReviewed(new Set());
      setSafetyOpen(result.questions.length > 0);
      setGoalEditing(false);
    } catch (caught) {
      setError(actionError(caught, "Task draft could not be compiled."));
    } finally {
      setPending(null);
    }
  }

  async function createProposed() {
    if (!accepted) return;
    setPending("propose");
    setError(null);
    setNotice(null);
    try {
      const result = await draftContract({
        raw_prompt: rawPrompt,
        accepted_contract: accepted,
      });
      setPreview(result);
      setNotice("Task settings saved. The agent cannot act until you activate this task.");
    } catch (caught) {
      setError(actionError(caught, "Proposed contract could not be saved."));
    } finally {
      setPending(null);
    }
  }

  async function activate() {
    const proposed = preview?.proposed_contract;
    if (!proposed) return;
    setPending("activate");
    setError(null);
    setNotice(null);
    try {
      const result = await activateContract({
        contract_id: proposed.contract_id,
        expected_version: proposed.version,
        expected_active_task_id: activeContract?.task_id ?? null,
      });
      await refresh();
      setNotice("Task activated. Sentinel will use these settings for new requests.");
      setReceiptContract(result.active_contract);
    } catch (caught) {
      setError(
        actionError(
          caught,
          "Activation failed because task authority changed. Refresh and review again.",
        ),
      );
    } finally {
      setPending(null);
    }
  }

  return (
    <div>
      <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-[var(--faint)]">
        Tasks
      </p>
      <h1 className="mt-2 text-[30px] font-semibold tracking-[-0.045em]">
        {preview ? "Review the task contract" : "Create a protected task"}
      </h1>
      <p className="mt-2 max-w-2xl text-[13px] leading-6 text-[var(--subtext)]">
        {preview
          ? "Confirm exactly what the agent may do before the contract becomes active."
          : "Describe the result you want. Sentinel will turn it into boundaries you can review."}
      </p>

      {error ? (
        <Alert variant="destructive" className="mt-6">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>Action failed</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {notice ? (
        <Alert className="mt-6">
          <Check aria-hidden="true" />
          <AlertTitle>Control state updated</AlertTitle>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}

      <div
        className={`mt-9 ${
          preview
            ? "border-t border-[var(--line)] pt-6"
            : "grid items-stretch gap-8 xl:grid-cols-[minmax(0,0.92fr)_minmax(360px,1.08fr)]"
        }`}
      >
        {preview ? (
          <section className="mb-7">
            <div className="flex flex-wrap items-start justify-between gap-5">
              <div className="max-w-3xl">
                <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--faint)]">
                  Task goal
                </p>
                <p className="mt-2 text-[14px] leading-6 text-[var(--ink)]">
                  {rawPrompt}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant="secondary">Draft</Badge>
                <span className="text-[10px] text-[var(--subtext)]">
                  {preview.questions.length
                    ? `${preview.questions.length} choices needed`
                    : "Ready for review"}
                </span>
                <button
                  ref={editGoalRef}
                  type="button"
                  className="link-draw text-[11px] text-[var(--subtext)] hover:text-[var(--ink)]"
                  onClick={() => setGoalEditing((current) => !current)}
                >
                  {goalEditing ? "Close editor" : "Edit goal"}
                </button>
              </div>
            </div>

            {goalEditing ? (
              <form
                onSubmit={compile}
                className="mt-5 flex flex-col gap-3 border-l-2 border-[var(--main)] pl-4"
              >
                <label htmlFor="task-prompt-edit" className="sr-only">
                  Task goal
                </label>
                <Textarea
                  id="task-prompt-edit"
                  value={rawPrompt}
                  onChange={(event) => setRawPrompt(event.target.value)}
                  maxLength={32_000}
                  className="min-h-28"
                  required
                />
                <Button
                  type="submit"
                  variant="secondary"
                  size="sm"
                  className="self-end"
                  disabled={pending !== null}
                >
                  {pending === "compile" ? "Preparing…" : "Rebuild settings"}
                </Button>
              </form>
            ) : null}
          </section>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle>What outcome do you want?</CardTitle>
            </CardHeader>
            <CardContent>
              <form
                id="task-draft-form"
                onSubmit={compile}
                className="flex h-full flex-col gap-4"
              >
                <label
                  htmlFor="task-prompt"
                  className="text-[12px] font-medium text-[var(--ink)]"
                >
                  Task goal
                </label>
                <Textarea
                  id="task-prompt"
                  value={rawPrompt}
                  onChange={(event) => setRawPrompt(event.target.value)}
                  placeholder="Create a result file in the build folder."
                  maxLength={32_000}
                  className="min-h-36"
                  required
                />
                <span className="text-[10px] leading-5 text-[var(--faint)]">
                  Your words prepare a draft only. Nothing becomes active until
                  you review and activate the contract.
                </span>
              </form>
            </CardContent>
          </Card>
        )}

        {!preview ? (
          <button
            type="submit"
            form="task-draft-form"
            aria-label="Build task settings"
            disabled={pending !== null}
            className="group relative min-h-[330px] overflow-hidden rounded-[8px] border-2 border-black bg-[#0b0b0d] p-8 text-left text-white shadow-[5px_5px_0_0_var(--main)] outline-none transition-transform hover:-translate-y-0.5 focus-visible:ring-4 focus-visible:ring-[rgba(136,170,238,0.45)] disabled:cursor-not-allowed disabled:hover:translate-y-0"
          >
            <span className="absolute inset-x-8 top-8 text-[10px] font-medium uppercase tracking-[0.12em] text-white/45">
              Sentinel contract
            </span>
            <span className="absolute bottom-8 left-8 max-w-[250px]">
              <span className="block text-[28px] font-medium leading-[1.05] tracking-[-0.04em]">
                {pending === "compile" ? "Preparing the contract" : "Behind the contract"}
              </span>
              <span className="mt-4 grid size-10 place-items-center rounded-full bg-white text-black transition-transform duration-200 group-hover:translate-x-1 group-hover:-translate-y-1">
                <ArrowUpRight aria-hidden="true" size={18} />
              </span>
              <span className="mt-5 block text-[11px] leading-5 text-white/55">
                {rawPrompt.trim()
                  ? "Open the boundaries Sentinel prepared from your task."
                  : "Describe a task on the left to reveal its protected boundaries."}
              </span>
            </span>
            <span
              aria-hidden="true"
              className="absolute -right-16 -top-16 size-52 rounded-full border border-white/10 transition-transform duration-300 group-hover:scale-110"
            />
            <span
              aria-hidden="true"
              className="absolute -right-5 top-20 size-28 rounded-full border border-[var(--main)]/50"
            />
          </button>
        ) : null}

        <Card className={preview ? undefined : "hidden"}>
          <CardHeader>
            <div className="flex items-start justify-between gap-4">
              <div>
                <CardTitle>Task contract</CardTitle>
                <p className="mt-1 text-[12px] text-[var(--subtext)]">
                  The boundary Sentinel will enforce for actions routed through
                  it.
                </p>
              </div>
              <Badge variant={proposedIsActive ? "default" : "secondary"}>
                {proposedIsActive
                  ? "Active"
                  : preview?.proposed_contract
                    ? "Ready to activate"
                    : "Needs review"}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            {!preview ? (
              <div className="grid min-h-[420px] place-items-center text-center">
                <div className="max-w-sm">
                  <FileCheck2
                    aria-hidden="true"
                    size={22}
                    className="mx-auto text-[var(--faint)]"
                  />
                  <p className="mt-4 text-[14px] font-semibold">
                    No task settings yet
                  </p>
                  <p className="mt-2 text-[12px] leading-5 text-[var(--subtext)]">
                    Describe the task first. Sentinel will turn it into clear
                    settings for you to review.
                  </p>
                </div>
              </div>
            ) : (
              <div className="flex flex-col gap-5">
                <fieldset
                  disabled={Boolean(preview.proposed_contract)}
                  className="flex flex-col gap-5 disabled:opacity-70"
                >
                  <legend className="sr-only">Contract boundaries</legend>
                <div className="grid gap-4 sm:grid-cols-2">
                  <ReviewField
                    label="Operation"
                    field="operation"
                    source={sources.get("operation")}
                    reviewed={reviewed}
                    onReview={setReviewed}
                  >
                    <Select
                      value={form.operation}
                      onValueChange={(value) =>
                        setForm({ ...form, operation: value })
                      }
                    >
                      <SelectTrigger id="contract-operation">
                        <SelectValue placeholder="Choose one" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {[
                            "read",
                            "write",
                            "delete",
                            "execute",
                            "network",
                            "external_communication",
                            "credential_access",
                          ].map((value) => (
                            <SelectItem key={value} value={value}>
                              {value.replaceAll("_", " ")}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </ReviewField>
                  <ReviewField
                    label="Environment"
                    field="environment"
                    source={sources.get("environment")}
                    reviewed={reviewed}
                    onReview={setReviewed}
                  >
                    <Select
                      value={form.environment}
                      onValueChange={(value) =>
                        setForm({ ...form, environment: value })
                      }
                    >
                      <SelectTrigger id="contract-environment">
                        <SelectValue placeholder="Choose one" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {["sandbox", "dev", "staging", "production"].map(
                            (value) => (
                              <SelectItem key={value} value={value}>
                                {value}
                              </SelectItem>
                            ),
                          )}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </ReviewField>
                </div>

                <ReviewField
                  label={
                    form.toolFamily === "sentinel_issue_fixture"
                      ? "Allowed fixture issues"
                      : "Allowed locations"
                  }
                  field="exact_targets"
                  source={sources.get("exact_targets")}
                  reviewed={reviewed}
                  onReview={setReviewed}
                >
                  {integration ? (
                    <div className="mb-2 flex flex-wrap items-center gap-2 text-[11px]">
                      <span className="text-[var(--subtext)]">Target kind</span>
                      <Select
                        value={form.toolFamily}
                        onValueChange={(value) => {
                          const toolFamily = value as DraftForm["toolFamily"];
                          const fixture = toolFamily === "sentinel_issue_fixture";
                          setForm({
                            ...form,
                            toolFamily,
                            // Fixture tools have no dry-run, rollback, transaction,
                            // or backup mode; leaving any of these on would make
                            // every real call fail closed.
                            dryRunRequired: fixture ? "no" : form.dryRunRequired,
                            rollbackRequired: fixture ? false : form.rollbackRequired,
                            transactionRequired: fixture
                              ? false
                              : form.transactionRequired,
                            backupRequired: fixture ? false : form.backupRequired,
                          });
                        }}
                      >
                        <SelectTrigger
                          id="contract-tool-family"
                          aria-label="Target kind"
                          className="h-8 w-auto min-w-[220px]"
                        >
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectItem value="shell">
                              Workspace files (shell)
                            </SelectItem>
                            <SelectItem value="sentinel_issue_fixture">
                              Fixture issues (Cursor MCP)
                            </SelectItem>
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </div>
                  ) : null}
                  <Textarea
                    id="contract-exact-targets"
                    value={form.exactTargets}
                    onChange={(event) =>
                      setForm({ ...form, exactTargets: event.target.value })
                    }
                    placeholder={
                      form.toolFamily === "sentinel_issue_fixture"
                        ? "One issue ID per line, for example SPIKE-1"
                        : "Choose the exact file or folder"
                    }
                    className="min-h-20 font-mono text-[12px]"
                  />
                  {form.toolFamily === "sentinel_issue_fixture" ? (
                    <p className="mt-1.5 text-[10px] leading-4 text-[var(--subtext)]">
                      Reads are always included. Writes add one reviewed note per
                      approval. The startup ceiling limits which issue IDs are valid.
                    </p>
                  ) : null}
                </ReviewField>

                <details
                  className="rounded-[5px] border border-[var(--line-strong)] bg-white"
                  open={safetyOpen}
                  onToggle={(event) =>
                    setSafetyOpen(event.currentTarget.open)
                  }
                >
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-4 py-3 text-[12px] font-semibold outline-none hover:bg-[var(--main-faint)] focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-inset">
                    <span>Safety and recovery</span>
                    <span className="text-[10px] font-normal text-[var(--subtext)]">
                      {preview.questions.length
                        ? `${preview.questions.length} choices needed`
                        : "Review safeguards"}
                    </span>
                  </summary>
                  <div className="flex flex-col gap-5 border-t border-[var(--line)] p-4">
                    {preview.questions.length ? (
                      <div className="border-l-2 border-[var(--main)] pl-3">
                        <p className="text-[11px] font-semibold">
                          Complete these choices
                        </p>
                        <ul className="mt-1.5 flex flex-col gap-1">
                          {preview.questions.map((question) => (
                            <li
                              key={question.question_id}
                              className="text-[10px] leading-5 text-[var(--subtext)]"
                            >
                              {question.prompt}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ) : null}

                    <ReviewField
                      label="Expected outcome"
                      field="expected_side_effects"
                      source={sources.get("expected_side_effects")}
                      reviewed={reviewed}
                      onReview={setReviewed}
                    >
                      <Textarea
                        id="contract-expected-side-effects"
                        value={form.expectedSideEffects}
                        onChange={(event) =>
                          setForm({
                            ...form,
                            expectedSideEffects: event.target.value,
                          })
                        }
                        className="min-h-20"
                      />
                    </ReviewField>

                    <ReviewField
                      label="If something goes wrong"
                      field="rollback_plan"
                      source={sources.get("rollback_plan")}
                      reviewed={reviewed}
                      onReview={setReviewed}
                    >
                      <Textarea
                        id="contract-rollback-plan"
                        value={form.rollbackPlan}
                        onChange={(event) =>
                          setForm({ ...form, rollbackPlan: event.target.value })
                        }
                        className="min-h-20"
                      />
                    </ReviewField>

                    {form.toolFamily !== "sentinel_issue_fixture" ? (
                    <ReviewField
                      label="Run a dry run first"
                      field="dry_run_required"
                      source={sources.get("dry_run_required")}
                      reviewed={reviewed}
                      onReview={setReviewed}
                    >
                      <Select
                        value={form.dryRunRequired}
                        onValueChange={(value) =>
                          setForm({
                            ...form,
                            dryRunRequired: value as "yes" | "no",
                          })
                        }
                      >
                        <SelectTrigger id="contract-dry-run-required">
                          <SelectValue placeholder="Choose one" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectItem value="yes">
                              Yes — the agent must preview shell changes before applying them
                            </SelectItem>
                            <SelectItem value="no">
                              No — apply directly after the other checks
                            </SelectItem>
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </ReviewField>
                    ) : null}

                    <div className="grid gap-4 sm:grid-cols-2">
                  <ReviewField
                    label="Allowed changes"
                    field="allowed_effects"
                    source={sources.get("allowed_effects")}
                    reviewed={reviewed}
                    onReview={setReviewed}
                  >
                    <Input
                      id="contract-allowed-effects"
                      value={form.allowedEffects}
                      onChange={(event) =>
                        setForm({ ...form, allowedEffects: event.target.value })
                      }
                      placeholder="write"
                    />
                  </ReviewField>
                  <ReviewField
                    label="Task expires in minutes"
                    field="expires_in_minutes"
                    source={sources.get("expires_in_minutes")}
                    reviewed={reviewed}
                    onReview={setReviewed}
                  >
                    <Input
                      id="contract-expires-in-minutes"
                      type="number"
                      min={1}
                      max={1440}
                      value={form.expiresInMinutes}
                      onChange={(event) =>
                        setForm({
                          ...form,
                          expiresInMinutes: event.target.value,
                        })
                      }
                    />
                      </ReviewField>
                    </div>
                  </div>
                </details>

                <details className="rounded-[5px] border-2 border-black bg-white shadow-[4px_4px_0_0_#000]">
                  <summary className="cursor-pointer bg-[var(--main)] px-4 py-3 text-[12px] font-semibold">
                    Advanced settings
                  </summary>
                  <div className="flex flex-col gap-4 border-t border-[var(--line)] p-4">
                    <ReviewField
                      label="Forbidden operations"
                      field="forbidden_operations"
                      source={sources.get("forbidden_operations")}
                      reviewed={reviewed}
                      onReview={setReviewed}
                    >
                      <Input
                        id="contract-forbidden-operations"
                        value={form.forbiddenOperations}
                        onChange={(event) =>
                          setForm({
                            ...form,
                            forbiddenOperations: event.target.value,
                          })
                        }
                      />
                    </ReviewField>
                    <ReviewField
                      label="Forbidden effects"
                      field="forbidden_effects"
                      source={sources.get("forbidden_effects")}
                      reviewed={reviewed}
                      onReview={setReviewed}
                    >
                      <Textarea
                        id="contract-forbidden-effects"
                        value={form.forbiddenEffects}
                        onChange={(event) =>
                          setForm({
                            ...form,
                            forbiddenEffects: event.target.value,
                          })
                        }
                        className="min-h-20"
                      />
                    </ReviewField>
                    <ReviewField
                      label="Forbidden effect codes"
                      field="forbidden_effect_codes"
                      source={sources.get("forbidden_effect_codes")}
                      reviewed={reviewed}
                      onReview={setReviewed}
                    >
                      <Input
                        id="contract-forbidden-effect-codes"
                        value={form.forbiddenEffectCodes}
                        onChange={(event) =>
                          setForm({
                            ...form,
                            forbiddenEffectCodes: event.target.value,
                          })
                        }
                      />
                    </ReviewField>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <BoundaryReview
                        field="allowed_tools"
                        label="Tool"
                        value="shell only"
                        source={sources.get("allowed_tools")}
                        reviewed={reviewed}
                        onReview={setReviewed}
                      />
                      <BoundaryReview
                        field="maximum_scope"
                        label="Maximum scope"
                        value="exact"
                        source={sources.get("maximum_scope")}
                        reviewed={reviewed}
                        onReview={setReviewed}
                      />
                    </div>
                    {form.toolFamily !== "sentinel_issue_fixture" ? (
                    <fieldset>
                      <legend className="text-[12px] font-medium">
                        Required safeguards
                      </legend>
                      <div className="mt-3 grid gap-2 sm:grid-cols-2">
                        {[
                          ["rollbackRequired", "Rollback", "rollback_required"],
                          [
                            "transactionRequired",
                            "Transaction",
                            "transaction_required",
                          ],
                          ["backupRequired", "Backup", "backup_required"],
                        ].map(([key, label, field]) => (
                          <div
                            key={key}
                            className="flex items-center gap-2 rounded-lg border border-[var(--line)] bg-white px-3 py-2 text-[12px]"
                          >
                            <input
                              id={`contract-safeguard-${key}`}
                              type="checkbox"
                              checked={Boolean(form[key as keyof DraftForm])}
                              onChange={(event) =>
                                setForm({
                                  ...form,
                                  [key]: event.target.checked,
                                })
                              }
                            />
                            <label htmlFor={`contract-safeguard-${key}`}>
                              {label}
                            </label>
                            {sources.has(field) ? (
                              <Badge variant="secondary">
                                {suggestionSourceLabel(sources.get(field)!.source)}
                              </Badge>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    </fieldset>
                    ) : null}
                    {preview.proposed_contract?.contract ?? accepted ? (
                      <details className="border-t border-[var(--line)] pt-4">
                        <summary className="w-fit cursor-pointer text-[11px] font-medium outline-none focus-visible:ring-2 focus-visible:ring-black">
                          Raw contract JSON
                        </summary>
                        <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-[5px] bg-[#0b0b0d] p-4 font-mono text-[10px] leading-5 text-white">
                          {JSON.stringify(
                            preview.proposed_contract?.contract ?? accepted,
                            null,
                            2,
                          )}
                        </pre>
                      </details>
                    ) : null}
                  </div>
                </details>
                </fieldset>

                {!allSuggestedReviewed ? (
                  <p className="text-[12px] text-[var(--subtext)]">
                    Confirm the settings that decide what the agent may do:
                    operation, allowed locations, environment, allowed changes,
                    and expiry. Other suggestions are accepted unless you change
                    them.
                  </p>
                ) : null}
                {preview.proposed_contract && !proposedIsActive ? (
                  <p className="text-[11px] text-[var(--subtext)]">
                    This saved proposal is locked. Edit the task goal and
                    rebuild to change its boundaries.
                  </p>
                ) : null}

                <div className="flex flex-wrap justify-end gap-2 border-t border-[var(--line)] pt-5">
                  {preview.proposed_contract ? (
                    proposedIsActive ? (
                      <Badge>Active task</Badge>
                    ) : (
                      <Button
                        onClick={activate}
                        disabled={pending !== null}
                      >
                        {pending === "activate"
                          ? "Activating…"
                          : "Activate task"}
                      </Button>
                    )
                  ) : (
                    <Button
                      onClick={createProposed}
                      disabled={!canPropose || pending !== null}
                    >
                      {pending === "propose"
                        ? "Saving proposal…"
                        : "Save task settings"}
                    </Button>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <ActivationReceipt
        contract={receiptContract}
        onClose={() => {
          setReceiptContract(null);
          requestAnimationFrame(() => editGoalRef.current?.focus());
        }}
      />
    </div>
  );
}

function ActivationReceipt({
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
  const expires = contract?.expires_at
    ? formatReceiptExpiry(contract.expires_at)
    : "Not specified";

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby="activation-receipt-title"
      className="m-auto w-[min(92vw,720px)] max-w-none overflow-visible border-0 bg-transparent p-0 backdrop:bg-black/72"
      onClose={onClose}
    >
      <div className="contract-receipt relative overflow-hidden rounded-[18px] border-2 border-black bg-[var(--main)] px-8 py-9 text-black shadow-[12px_12px_0_0_#000] sm:px-12 sm:py-11">
        <span
          aria-hidden="true"
          className="absolute -left-5 top-1/2 size-10 -translate-y-1/2 rounded-full bg-black"
        />
        <span
          aria-hidden="true"
          className="absolute -right-5 top-1/2 size-10 -translate-y-1/2 rounded-full bg-black"
        />
        <div className="flex items-start justify-between gap-8">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.12em]">
              Sentinel authorization
            </p>
            <h2
              id="activation-receipt-title"
              className="mt-3 text-[34px] font-semibold tracking-[-0.05em]"
            >
              Contract active
            </h2>
          </div>
          <span className="grid size-10 place-items-center rounded-full border-2 border-black bg-white">
            <Check aria-hidden="true" size={19} strokeWidth={2.4} />
          </span>
        </div>

        <p className="mt-8 max-w-xl text-[15px] font-medium leading-6">
          {objective}
        </p>

        <dl className="mt-8 grid gap-5 border-y border-black/25 py-6 sm:grid-cols-3">
          <ReceiptFact label="Operation" value={operation.replaceAll("_", " ")} />
          <ReceiptFact label="Environment" value={environment} />
          <ReceiptFact label="Expires" value={expires} />
        </dl>

        <div className="mt-7 flex flex-wrap items-center justify-between gap-4">
          <p className="max-w-sm text-[11px] leading-5 text-black/75">
            Sentinel will enforce these boundaries for actions routed through
            it and ask before important changes.
          </p>
          <Button
            type="button"
            variant="neutral"
            autoFocus
            onClick={onClose}
          >
            Done
          </Button>
        </div>
      </div>
    </dialog>
  );
}

function ReceiptFact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[9px] font-semibold uppercase tracking-[0.1em] text-black/75">
        {label}
      </dt>
      <dd className="mt-1.5 text-[13px] font-semibold capitalize">{value}</dd>
    </div>
  );
}

function formatReceiptExpiry(value: string) {
  const remainingMs = new Date(value).getTime() - Date.now();
  const remainingMinutes = Math.max(1, Math.round(remainingMs / 60_000));
  return `${remainingMinutes} minutes`;
}

function ReviewField({
  label,
  field,
  source,
  reviewed,
  onReview,
  children,
}: {
  label: string;
  field: string;
  source?: DraftSuggestionResponse;
  reviewed: Set<string>;
  onReview: (next: Set<string>) => void;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex min-h-5 items-center gap-2">
        <label
          htmlFor={`contract-${field.replaceAll("_", "-")}`}
          className="text-[12px] font-medium"
        >
          {label}
        </label>
        {source ? (
          <>
            <Badge variant="secondary">
              {suggestionSourceLabel(source.source)}
            </Badge>
            {AUTHORITY_FIELDS.has(field) ? (
              <ReviewToggle
                field={field}
                reviewed={reviewed}
                onReview={onReview}
              />
            ) : null}
          </>
        ) : (
          <Badge variant="outline">Your answer</Badge>
        )}
      </div>
      {children}
    </div>
  );
}

function ReviewToggle({
  field,
  reviewed,
  onReview,
}: {
  field: string;
  reviewed: Set<string>;
  onReview: (next: Set<string>) => void;
}) {
  return (
    <label className="ml-auto flex items-center gap-1.5 text-[10px] text-[var(--subtext)]">
      <input
        type="checkbox"
        checked={reviewed.has(field)}
        onChange={(event) => {
          const next = new Set(reviewed);
          if (event.target.checked) next.add(field);
          else next.delete(field);
          onReview(next);
        }}
      />
      Reviewed
    </label>
  );
}

function BoundaryReview({
  field,
  label,
  value,
  source,
  reviewed,
  onReview,
}: {
  field: string;
  label: string;
  value: string;
  source?: DraftSuggestionResponse;
  reviewed: Set<string>;
  onReview: (next: Set<string>) => void;
}) {
  return (
    <div className="rounded-lg border border-[var(--line)] bg-white p-3">
      <div className="flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-[0.07em] text-[var(--faint)]">
          {label}
        </span>
        {source && AUTHORITY_FIELDS.has(field) ? (
          <ReviewToggle
            field={field}
            reviewed={reviewed}
            onReview={onReview}
          />
        ) : null}
      </div>
      <p className="mt-1.5 font-mono text-[11px]">{value}</p>
    </div>
  );
}

function formFromSuggestions(
  suggestions: DraftSuggestionResponse[],
): DraftForm {
  const values = new Map(suggestions.map((item) => [item.field, item.value]));
  return {
    operation: stringValue(values.get("operation")),
    exactTargets: linesValue(values.get("exact_targets")),
    environment: stringValue(values.get("environment")),
    expectedSideEffects: linesValue(values.get("expected_side_effects")),
    allowedEffects: commaValue(values.get("allowed_effects")),
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

function acceptedContract(form: DraftForm): AcceptedContractDraft | null {
  const targets = nonemptyLines(form.exactTargets);
  const expectedEffects = nonemptyLines(form.expectedSideEffects);
  const allowedEffects = commaList(form.allowedEffects);
  const forbiddenEffects = nonemptyLines(form.forbiddenEffects);
  const expiry = Number(form.expiresInMinutes);
  if (
    !form.operation ||
    !form.environment ||
    targets.length === 0 ||
    expectedEffects.length === 0 ||
    allowedEffects.length === 0 ||
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
    exact_targets: targets,
    environment: form.environment as AcceptedContractDraft["environment"],
    expected_side_effects: expectedEffects,
    allowed_effects: allowedEffects,
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
  return typeof value === "string" || typeof value === "number"
    ? String(value)
    : "";
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

function suggestionSourceLabel(
  source: DraftSuggestionResponse["source"],
) {
  return source === "safe_default"
    ? "Safe default"
    : source === "prompt_explicit"
      ? "From your task"
      : "Suggested";
}

function actionError(error: unknown, fallback: string) {
  if (error instanceof ControlApiError && error.status === 401) {
    return "Control session expired. Open a fresh pairing link.";
  }
  return fallback;
}
