import type { ReactNode } from "react";

import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@/components/ui/empty";

export function SectionPlaceholder({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <div>
      <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-[var(--faint)]">
        {eyebrow}
      </p>
      <h1 className="mt-1.5 text-2xl font-semibold tracking-[-0.035em]">
        {title}
      </h1>
      <p className="mt-2 max-w-2xl text-[13px] leading-5 text-[var(--subtext)]">
        {description}
      </p>
      <section className="mt-8">{children}</section>
    </div>
  );
}

export function EmptyState({
  title,
  detail,
}: {
  title: string;
  detail: string;
}) {
  return (
    <Empty className="min-h-64">
      <EmptyHeader>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription>{detail}</EmptyDescription>
      </EmptyHeader>
    </Empty>
  );
}
