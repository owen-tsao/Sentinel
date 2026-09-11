import type { HTMLAttributes, ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * The authorization ticket: the one loud element on a page.
 *
 * Geometry (frame, shadow, punched notches) lives in globals.css under
 * `.ticket`; this component only lays out the content. `tone="idle"` renders
 * the same shape in white for "no task active" so the focus slot never
 * disappears, but nothing reads as granted.
 */
export function Ticket({
  tone = "active",
  paint = false,
  className,
  children,
  ...rest
}: {
  tone?: "active" | "idle";
  /** Animate the blue fill sweeping in; set only when the ticket just became active. */
  paint?: boolean;
  className?: string;
  children: ReactNode;
} & Omit<HTMLAttributes<HTMLElement>, "className" | "children">) {
  return (
    <section
      className={cn("ticket", className)}
      data-tone={tone}
      data-paint={paint && tone === "active" ? "true" : undefined}
      {...rest}
    >
      <div aria-hidden="true" className="ticket-shadow" />
      <div className="ticket-frame">
        <div className="ticket-fill px-6 pb-5 pt-[22px] sm:px-[30px]">{children}</div>
      </div>
    </section>
  );
}

/** Eyebrow + title + one-line context on the left, a seal (state word + mark) on the right. */
export function TicketHead({
  eyebrow,
  title,
  titleId,
  meta,
  seal,
}: {
  eyebrow: string;
  title: string;
  titleId: string;
  meta?: ReactNode;
  seal?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-6">
      <div className="min-w-0">
        <p className="text-[10px] font-semibold uppercase tracking-[0.12em] opacity-80">
          {eyebrow}
        </p>
        <h2
          id={titleId}
          className="mt-2 max-w-[30ch] text-[24px] font-semibold leading-[1.2] tracking-[-0.03em]"
        >
          {title}
        </h2>
        {meta ? <p className="mt-1.5 text-[12px] opacity-80">{meta}</p> : null}
      </div>
      {seal}
    </div>
  );
}

export function TicketSeal({ state, mark = "check" }: { state: string; mark?: "check" | "dot" }) {
  return (
    <div className="flex shrink-0 items-center gap-2.5">
      <span className="text-[11px] font-semibold uppercase tracking-[0.06em]">{state}</span>
      <span className="grid size-[30px] place-items-center rounded-full border-2 border-black bg-white">
        {mark === "check" ? (
          <svg viewBox="0 0 24 24" className="size-[15px] fill-none stroke-black stroke-[2.4]">
            <path d="M5 12.5l4.5 4.5L19 7.5" />
          </svg>
        ) : (
          <span aria-hidden="true" className="size-2 rounded-full bg-[var(--main)]" />
        )}
      </span>
    </div>
  );
}

/**
 * The facts block: a two-column grid between two rules, labels above values.
 * Item labels double as the accessible names tests and screen readers use.
 */
export function TicketFacts({ items }: { items: Array<{ label: string; value: ReactNode }> }) {
  return (
    <dl className="mt-3.5 grid grid-cols-1 gap-y-3 border-y-[1.5px] border-[var(--main-line)] py-3 sm:grid-cols-2 sm:gap-y-3">
      {items.map((item, index) => (
        <div
          key={item.label}
          className={cn(
            "min-w-0",
            index % 2 === 1 && "sm:border-l sm:border-[var(--main-line)] sm:pl-[18px]",
            index % 2 === 0 && "sm:pr-[18px]",
          )}
        >
          <dt className="text-[10px] font-semibold uppercase tracking-[0.1em] opacity-75">
            {item.label}
          </dt>
          <dd className="mt-1 text-[13px] font-semibold">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Note on the left, actions on the right; pinned to the ticket's bottom edge when the ticket is taller than its content. */
export function TicketFoot({ note, actions }: { note?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mt-auto flex flex-wrap items-center justify-between gap-4 pt-3.5">
      {note ? <p className="text-[12px] opacity-85">{note}</p> : <span />}
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** Mono identifier chip (target IDs, tool names) on a white tile inside the ticket. */
export function Chip({ children }: { children: ReactNode }) {
  return (
    <span className="mr-1 inline-block rounded-[5px] border-[1.5px] border-black bg-white px-1.5 font-mono text-[11px] font-medium leading-[17px] text-black">
      {children}
    </span>
  );
}
