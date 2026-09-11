import Link from "next/link";
import type { HTMLAttributes, ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * Shared layout primitives for the control center.
 *
 * Pages compose these instead of hand-rolling chrome. Column headers
 * (`PageHeader`, `SectionHeader` with `asColumnHead`) share one fixed height
 * so panels in neighbouring columns start on the same line.
 */

export const COLUMN_HEAD_CLASS = "h-5 mb-3.5";

export function Eyebrow({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <p
      className={cn(
        "text-[11px] font-medium uppercase tracking-[0.08em] text-[var(--faint)]",
        className,
      )}
    >
      {children}
    </p>
  );
}

/** Eyebrow + title line at the top of a page; optional single action on the right. */
export function PageHeader({
  eyebrow,
  title,
  action,
  className,
}: {
  eyebrow: string;
  title: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-baseline justify-between gap-6", COLUMN_HEAD_CLASS, className)}>
      <div className="flex min-w-0 items-baseline gap-3">
        <Eyebrow>{eyebrow}</Eyebrow>
        <h1 className="truncate text-[13px] font-semibold tracking-[-0.01em]">{title}</h1>
      </div>
      {action}
    </div>
  );
}

/** Eyebrow with an optional trailing link/status, used above any section. */
export function SectionHeader({
  label,
  trailing,
  id,
  className,
}: {
  label: string;
  trailing?: ReactNode;
  id?: string;
  className?: string;
}) {
  return (
    <div className={cn("flex items-baseline justify-between gap-4", className)}>
      <h2 id={id}>
        <Eyebrow>{label}</Eyebrow>
      </h2>
      {trailing}
    </div>
  );
}

/** Quiet trailing link for section headers ("Settings →", "Open activity →"). */
export function SectionLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link
      href={href}
      className="link-draw text-[12px] text-[var(--subtext)] hover:text-[var(--ink)]"
    >
      {children}
    </Link>
  );
}

/**
 * A white panel with the 1.5px black frame. Holds a genuinely separate object
 * (a grid, a log, a form); never wraps the page itself.
 */
export function Panel({
  className,
  children,
  ...rest
}: {
  className?: string;
  children: ReactNode;
} & Omit<HTMLAttributes<HTMLDivElement>, "className" | "children">) {
  return (
    <div
      className={cn(
        "rounded-[var(--radius-panel)] border-[1.5px] border-[var(--outline)] bg-[var(--paper)]",
        className,
      )}
      {...rest}
    >
      {children}
    </div>
  );
}

/**
 * Labels in a fixed-width grey column, values beside them. Reads as a
 * document, aligns without dividers. For 3–6 short facts.
 */
export function KeyValueList({
  items,
  className,
  labelWidth = "120px",
}: {
  items: Array<{ label: string; value: ReactNode }>;
  className?: string;
  labelWidth?: string;
}) {
  return (
    <dl
      className={cn("grid gap-x-6 gap-y-2.5 text-[13px]", className)}
      style={{ gridTemplateColumns: `${labelWidth} minmax(0, 1fr)` }}
    >
      {items.map((item) => (
        <div key={item.label} className="contents">
          <dt className="text-[var(--subtext)]">{item.label}</dt>
          <dd className="min-w-0 font-medium">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export type StatusTone = "ok" | "warn" | "off" | "muted" | "main";

const toneDot: Record<StatusTone, string> = {
  ok: "bg-[var(--dot-ok)]",
  warn: "bg-[var(--dot-warn)]",
  off: "bg-[var(--dot-off)]",
  muted: "bg-[var(--muted-signal)]",
  main: "bg-[var(--main)]",
};

/** A 6px status dot followed by a word. Colour is the signal; nothing else is tinted. */
export function StatusDot({
  tone,
  children,
  className,
}: {
  tone: StatusTone;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex items-center gap-2 text-[13px]", className)}>
      <span aria-hidden="true" className={cn("size-1.5 shrink-0 rounded-full", toneDot[tone])} />
      {children}
    </span>
  );
}

/** Table framed by a hairline above and below, never a box. Header row is eyebrow-styled. */
export function HairlineTable({
  headers,
  rows,
  align = [],
  className,
}: {
  headers: ReactNode[];
  rows: Array<{ key: string; cells: ReactNode[] }>;
  align?: Array<"left" | "right" | undefined>;
  className?: string;
}) {
  return (
    <table className={cn("w-full border-y border-[var(--line)] text-left text-[13px]", className)}>
      <thead>
        <tr className="border-b border-[var(--line)]">
          {headers.map((header, index) => (
            <th
              key={index}
              className={cn(
                "py-2 pr-6 text-[11px] font-medium uppercase tracking-[0.08em] text-[var(--faint)] last:pr-0",
                align[index] === "right" && "text-right",
              )}
            >
              {header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="divide-y divide-[var(--line)]">
        {rows.map((row) => (
          <tr key={row.key}>
            {row.cells.map((cell, index) => (
              <td
                key={index}
                className={cn("py-2.5 pr-6 align-top last:pr-0", align[index] === "right" && "text-right")}
              >
                {cell}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
