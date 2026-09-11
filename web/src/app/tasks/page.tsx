"use client";

import { CircleAlert } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";

import { ActivationReceipt, ContractTicket } from "@/components/contract-ticket";
import { useControl } from "@/components/control-provider";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { COLUMN_HEAD_CLASS, PageHeader, Panel, SectionHeader, StatusDot } from "@/components/ui/layout";
import { Textarea } from "@/components/ui/textarea";
import {
  activateContract,
  ControlApiError,
  draftContract,
  getTargetSuggestions,
  PROPOSAL_PREFILL_KEY,
} from "@/lib/control-api";
import type {
  ContractRecord,
  ContractDraftResponse,
  ProposalAdjustResponse,
  TargetSuggestionsResponse,
} from "@/lib/control-types";

import {
  acceptedContract,
  ContractForm,
  emptyForm,
  formFromAccepted,
  formFromSuggestions,
  type DraftForm,
} from "./contract-form";

/**
 * Tasks: goal → settings → one confirm → activate.
 *
 * Left: one panel holding the goal and, once built, the grouped settings with
 * a single blue "Confirm task settings" button at the bottom. Right: the
 * contract ticket, updating live, which carries the raised "Activate task"
 * once the settings are confirmed. Authority is still granted only by the
 * server on activation; the form never widens anything on its own.
 */
export default function TasksPage() {
  const { activeContract, refresh, status } = useControl();
  const integration = status?.integration ?? null;
  // Fixed at process launch; the server rejects any other environment.
  const fixedEnvironment = status?.runtime.execution_environment ?? null;
  const [rawPrompt, setRawPrompt] = useState("");
  const [preview, setPreview] = useState<ContractDraftResponse | null>(null);
  const [form, setForm] = useState<DraftForm>(emptyForm);
  const [suggestions, setSuggestions] = useState<TargetSuggestionsResponse | null>(null);
  const [goalEditing, setGoalEditing] = useState(false);
  const [receiptContract, setReceiptContract] = useState<ContractRecord | null>(null);
  const [justActivated, setJustActivated] = useState(false);
  const editGoalRef = useRef<HTMLButtonElement>(null);
  const [pending, setPending] = useState<"compile" | "confirm" | "activate" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const prefillApplied = useRef(false);
  // Set once the saved draft (if any) has been restored, so the save effect
  // below never overwrites it with the empty initial state.
  const restored = useRef(false);

  useEffect(() => {
    let cancelled = false;
    getTargetSuggestions()
      .then((result) => {
        if (!cancelled) setSuggestions(result);
      })
      .catch(() => {
        // Suggestions are a convenience; typing a path still works.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // "Adjust in full form" hands the agent's (already consumed) draft over via
  // session storage. It only prefills fields; the server re-validates on save.
  // Otherwise, restore whatever the user was typing before they switched tabs:
  // client-side navigation unmounts this page, and losing a half-filled
  // contract to a glance at Activity is not acceptable.
  useEffect(() => {
    if (prefillApplied.current) return;
    prefillApplied.current = true;
    const raw = window.sessionStorage.getItem(PROPOSAL_PREFILL_KEY);
    if (!raw) {
      void (async () => {
        const saved = readSavedDraft();
        if (saved) {
          setRawPrompt(saved.rawPrompt);
          setPreview(saved.preview);
          setForm(saved.form);
          setGoalEditing(saved.goalEditing);
        }
        restored.current = true;
      })();
      return;
    }
    window.sessionStorage.removeItem(PROPOSAL_PREFILL_KEY);
    restored.current = true;
    let prefill: ProposalAdjustResponse;
    try {
      prefill = JSON.parse(raw) as ProposalAdjustResponse;
    } catch {
      return;
    }
    if (!prefill?.accepted_contract || typeof prefill.raw_prompt !== "string") return;
    const { raw_prompt: prompt, accepted_contract: accepted } = prefill;
    void (async () => {
      setRawPrompt(prompt);
      setPending("compile");
      try {
        const result = await draftContract({ raw_prompt: prompt });
        setPreview(result);
        setForm(formFromAccepted(accepted));
        setNotice(
          "Prefilled from the agent's proposal. Review the settings before confirming; the proposal itself has been retired.",
        );
      } catch (caught) {
        setError(actionError(caught, "The proposal could not be loaded into the form."));
      } finally {
        setPending(null);
      }
    })();
  }, []);

  const confirmed = Boolean(preview?.proposed_contract);
  const proposedIsActive =
    confirmed &&
    activeContract !== null &&
    preview?.proposed_contract?.contract_id === activeContract?.contract_id &&
    preview?.proposed_contract?.version === activeContract?.version;

  useEffect(() => {
    if (!restored.current) return;
    // Once the task is active the draft has done its job; keeping it would
    // only bring back a stale "ready" ticket on the next visit.
    if (proposedIsActive) {
      clearSavedDraft();
      return;
    }
    writeSavedDraft({ rawPrompt, preview, form, goalEditing });
  }, [rawPrompt, preview, form, goalEditing, proposedIsActive]);

  const accepted = useMemo(() => acceptedContract(form), [form]);
  const operationForbidden =
    Boolean(form.operation) &&
    form.forbiddenOperations
      .split(",")
      .map((item) => item.trim())
      .includes(form.operation);
  const canConfirm = preview !== null && accepted !== null && !operationForbidden && !confirmed;

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
      setForm(formFromSuggestions(result.suggestions, fixedEnvironment));
      setGoalEditing(false);
    } catch (caught) {
      setError(actionError(caught, "Task draft could not be compiled."));
    } finally {
      setPending(null);
    }
  }

  async function confirm() {
    if (!accepted) return;
    setPending("confirm");
    setError(null);
    setNotice(null);
    try {
      const result = await draftContract({ raw_prompt: rawPrompt, accepted_contract: accepted });
      setPreview(result);
      setNotice("Task settings confirmed. The agent cannot act until you activate this task.");
    } catch (caught) {
      setError(actionError(caught, "Task settings could not be confirmed."));
    } finally {
      setPending(null);
    }
  }

  function unlock() {
    // Drop the confirmed copy locally; confirming again creates a fresh
    // proposed contract and the abandoned one can never be activated from here.
    setPreview((current) => (current ? { ...current, proposed_contract: null } : current));
    setNotice(null);
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
      // The ticket paints blue first; the receipt's own animation delay lets
      // that finish before it rises over the page.
      setJustActivated(true);
      setReceiptContract(result.active_contract);
    } catch (caught) {
      setError(
        actionError(caught, "Activation failed because task authority changed. Refresh and review again."),
      );
    } finally {
      setPending(null);
    }
  }

  function startOver() {
    setPreview(null);
    setForm(emptyForm);
    setRawPrompt("");
    setNotice(null);
    setError(null);
    setGoalEditing(false);
    setJustActivated(false);
    clearSavedDraft();
  }

  const stage: "empty" | "draft" | "ready" | "active" = !preview
    ? "empty"
    : proposedIsActive
      ? "active"
      : confirmed
        ? "ready"
        : "draft";

  return (
    <div className="grid gap-7 lg:h-[calc(100vh-52px-40px)] lg:grid-cols-[minmax(0,1.35fr)_minmax(320px,1fr)]">
      <div className="flex min-h-0 min-w-0 flex-col">
        <PageHeader
          eyebrow="Tasks"
          title={preview ? "Review the task contract" : "Create a protected task"}
        />

        {error ? (
          <Alert variant="destructive" className="mb-4">
            <CircleAlert aria-hidden="true" />
            <AlertTitle>Action failed</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}

        {/* The panel fills the column; the goal and settings scroll inside it
            while the confirm footer stays pinned, so the whole flow fits one
            screen beside the ticket. */}
        <Panel className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
            <section aria-labelledby="goal-heading" className="px-5 py-4">
              <div className="flex items-baseline justify-between gap-4">
                <h2 id="goal-heading" className="text-[14px] font-semibold tracking-[-0.01em]">
                  Goal
                </h2>
                {preview ? (
                  <button
                    ref={editGoalRef}
                    type="button"
                    className="link-draw text-[12px] text-[var(--subtext)] hover:text-[var(--ink)]"
                    onClick={() => setGoalEditing((current) => !current)}
                  >
                    {goalEditing ? "Close editor" : "Edit goal"}
                  </button>
                ) : null}
              </div>
              {!preview || goalEditing ? (
                <form id="task-draft-form" onSubmit={compile} className="mt-3 flex flex-col gap-3">
                  <label htmlFor="task-prompt" className="sr-only">
                    Task goal
                  </label>
                  <Textarea
                    id="task-prompt"
                    value={rawPrompt}
                    onChange={(event) => setRawPrompt(event.target.value)}
                    placeholder="Create /workspace/build/result.txt in sandbox."
                    maxLength={32_000}
                    className={preview ? "min-h-24" : "min-h-32"}
                    required
                  />
                  <div className="flex items-center justify-between gap-4">
                    <p className="text-[12px] text-[var(--subtext)]">
                      Your words only prepare a draft. Nothing is active until you confirm and
                      activate.
                    </p>
                    <Button
                      type="submit"
                      variant="secondary"
                      aria-label="Build task settings"
                      disabled={pending !== null}
                    >
                      {pending === "compile" ? "Preparing…" : preview ? "Rebuild settings" : "Build settings"}
                    </Button>
                  </div>
                </form>
              ) : (
                <p className="mt-2 text-[13px] leading-5">{rawPrompt}</p>
              )}
            </section>

            {preview ? (
              <ContractForm
                form={form}
                setForm={setForm}
                preview={preview}
                locked={confirmed}
                fixedEnvironment={fixedEnvironment}
                integration={integration}
                suggestions={suggestions}
                operationForbidden={operationForbidden}
                accepted={accepted}
              />
            ) : (
              <HowItWorks replacesActive={activeContract !== null} />
            )}
          </div>

          {preview ? (
            <div className="flex flex-wrap items-center justify-between gap-4 border-t border-[var(--line)] px-5 py-4">
              {proposedIsActive ? (
                <>
                  <StatusDot tone="ok" className="font-medium">
                    Active task
                  </StatusDot>
                  <Button variant="quiet" className="text-[var(--subtext)]" onClick={startOver}>
                    Create another task
                  </Button>
                </>
              ) : confirmed ? (
                <>
                  <p role="status" className="text-[12px] text-[var(--subtext)]">
                    {notice ?? "Settings confirmed. Activate the task from the ticket."}
                  </p>
                  <Button variant="quiet" className="text-[var(--subtext)]" onClick={unlock}>
                    Edit settings
                  </Button>
                </>
              ) : (
                <>
                  <p role="status" className="text-[12px] text-[var(--subtext)]">
                    {notice ??
                      (accepted
                        ? "Confirming locks these settings so you can activate the task."
                        : "Fill in the highlighted answers to confirm.")}
                  </p>
                  <Button
                    size="lg"
                    onClick={confirm}
                    disabled={!canConfirm || pending !== null}
                    className="min-w-[200px]"
                  >
                    {pending === "confirm" ? "Confirming…" : "Confirm task settings"}
                  </Button>
                </>
              )}
            </div>
          ) : null}
        </Panel>
      </div>

      <div className="flex min-h-0 min-w-0 flex-col">
        <SectionHeader label="Task contract" className={COLUMN_HEAD_CLASS} />
        <ContractTicket
          className="min-h-0 flex-1"
          stage={stage}
          paint={justActivated && stage === "active"}
          preview={
            accepted || form.operation || form.exactTargets.length
              ? {
                  operation: form.operation,
                  environment: form.environment,
                  targets: form.exactTargets,
                  expiresInMinutes: Number(form.expiresInMinutes) || null,
                }
              : null
          }
          contract={
            proposedIsActive ? activeContract : confirmed ? preview?.proposed_contract ?? null : null
          }
          onActivate={activate}
          activating={pending === "activate"}
          replacesActive={Boolean(activeContract) && !proposedIsActive}
        />
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

/**
 * Fills the left panel before anything is drafted, so the empty state teaches
 * the three steps instead of leaving a bare goal box over blank space.
 */
function HowItWorks({ replacesActive }: { replacesActive: boolean }) {
  const steps: Array<[string, string]> = [
    ["Describe the goal", "Plain words are enough. Sentinel turns them into a draft of exact settings."],
    ["Confirm the settings", "Check the operation, the exact paths, and what happens if it goes wrong. Nothing is granted yet."],
    ["Activate the task", "The ticket turns blue. The agent may act only inside these boundaries, and each write pauses for you."],
  ];
  return (
    <section
      aria-labelledby="how-it-works-heading"
      className="flex flex-1 flex-col border-t border-[var(--line)] px-5 pt-4"
    >
      <h2 id="how-it-works-heading" className="text-[14px] font-semibold tracking-[-0.01em]">
        How a task works
      </h2>
      {/* Each step takes an equal share of the remaining height so the panel
          reads as three rows, not a list floating over blank space. */}
      <ol className="mt-2 flex flex-1 flex-col divide-y divide-[var(--line)]">
        {steps.map(([title, detail], index) => (
          <li key={title} className="grid flex-1 grid-cols-[28px_minmax(0,1fr)] content-center gap-x-3 py-4">
            <span
              aria-hidden="true"
              className="grid size-6 place-items-center rounded-full border-[1.5px] border-[var(--outline)] font-mono text-[11px] font-medium"
            >
              {index + 1}
            </span>
            <div className="pt-0.5">
              <p className="text-[13px] font-medium">{title}</p>
              <p className="mt-0.5 max-w-[52ch] text-[12px] leading-5 text-[var(--subtext)]">{detail}</p>
            </div>
          </li>
        ))}
      </ol>
      {replacesActive ? (
        <p className="border-t border-[var(--line)] py-4 text-[12px] leading-5 text-[var(--subtext)]">
          A task is already active. Activating a new one replaces it; the agent keeps the current
          boundaries until then.
        </p>
      ) : null}
    </section>
  );
}

const DRAFT_STORAGE_KEY = "sentinel.task-draft.v1";

type SavedDraft = {
  rawPrompt: string;
  preview: ContractDraftResponse | null;
  form: DraftForm;
  goalEditing: boolean;
};

/** Per-tab only (sessionStorage); the server still validates everything on confirm and activate. */
function readSavedDraft(): SavedDraft | null {
  try {
    const raw = window.sessionStorage.getItem(DRAFT_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<SavedDraft>;
    if (typeof parsed.rawPrompt !== "string" || !parsed.form) return null;
    // A confirmed copy is a server-side object that may no longer exist
    // (restart, expiry, replacement). Come back as an unlocked draft so the
    // user re-confirms and the server issues a fresh one; never as "ready".
    const preview = parsed.preview ? { ...parsed.preview, proposed_contract: null } : null;
    return {
      rawPrompt: parsed.rawPrompt,
      preview,
      form: { ...emptyForm, ...parsed.form },
      goalEditing: Boolean(parsed.goalEditing),
    };
  } catch {
    return null;
  }
}

function writeSavedDraft(draft: SavedDraft) {
  try {
    if (!draft.rawPrompt && !draft.preview) {
      window.sessionStorage.removeItem(DRAFT_STORAGE_KEY);
      return;
    }
    window.sessionStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(draft));
  } catch {
    // Storage full or blocked: the form still works, it just will not survive navigation.
  }
}

function clearSavedDraft() {
  try {
    window.sessionStorage.removeItem(DRAFT_STORAGE_KEY);
  } catch {
    // Nothing to clear.
  }
}

function actionError(error: unknown, fallback: string) {
  if (error instanceof ControlApiError) {
    if (error.status === 401) {
      return "Control session expired. Open a fresh pairing link.";
    }
    // 404/409/422 reasons are written by the server for people; show them so
    // the user can fix the input instead of guessing.
    if ((error.status === 404 || error.status === 409 || error.status === 422) && error.detail) {
      return `${fallback} ${error.detail}`;
    }
  }
  return fallback;
}
