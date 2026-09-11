"use client";

import type { ReactNode } from "react";

import { Badge } from "@/components/ui/badge";
import { StatusDot } from "@/components/ui/layout";
import type { DraftSuggestionResponse } from "@/lib/control-types";

import { suggestionSourceLabel } from "./draft-form";

/** Label line (label · source tag · "Needs your answer") above the control. */
export function Field({
  label,
  htmlFor,
  source,
  question,
  hint,
  problem,
  trailing,
  children,
}: {
  label: string;
  htmlFor: string;
  source?: DraftSuggestionResponse;
  question?: string;
  hint?: string;
  problem?: string;
  trailing?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <div className="flex min-h-5 flex-wrap items-center gap-2">
        <label htmlFor={htmlFor} className="text-[12px] font-medium">
          {label}
        </label>
        {source ? <Badge variant="secondary">{suggestionSourceLabel(source.source)}</Badge> : null}
        {question ? (
          <StatusDot tone="warn" className="text-[11px] text-[var(--subtext)]">
            Needs your answer
          </StatusDot>
        ) : null}
        {trailing ? <span className="ml-auto">{trailing}</span> : null}
      </div>
      {children}
      {problem ? (
        <p className="text-[12px] text-[var(--danger)]">{problem}</p>
      ) : question ? (
        <p id={`${htmlFor}-hint`} className="text-[12px] leading-4 text-[var(--subtext)]">
          {question}
        </p>
      ) : hint ? (
        <p id={`${htmlFor}-hint`} className="text-[11px] leading-4 text-[var(--faint)]">
          {hint}
        </p>
      ) : null}
    </div>
  );
}
