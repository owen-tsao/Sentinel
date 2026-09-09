"use client";

import Link from "next/link";

import { useControl } from "@/components/control-provider";
import { Button } from "@/components/ui/button";

const sectionLabelClass =
  "text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--faint)]";

export default function Home() {
  const { status, activeContract, approvalCount } = useControl();

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#4f6fad]">
            Overview
          </p>
          <h1 className="mt-2 text-[30px] font-semibold tracking-[-0.045em]">
            Your workspace
          </h1>
          <p className="mt-2 max-w-2xl text-[13px] leading-6 text-[var(--subtext)]">
            See what your agent can do, review anything that needs attention,
            and adjust your preferences.
          </p>
        </div>
        {!activeContract ? (
          <Button asChild>
            <Link href="/tasks">Create a task</Link>
          </Button>
        ) : null}
      </div>

      <div className="mt-12 grid gap-x-16 gap-y-12 xl:grid-cols-[minmax(0,1.35fr)_minmax(270px,0.65fr)]">
        <section className="border-l-2 border-[var(--main)] pl-5 xl:col-start-1 xl:row-start-1">
            <p className={sectionLabelClass}>Current task</p>
            <h2 className="mt-2 max-w-2xl text-[22px] font-medium tracking-[-0.025em]">
              {activeContract?.contract.objective ?? "No task is active"}
            </h2>
            <p className="mt-2 text-[12px] text-[var(--subtext)]">
              {activeContract
                ? "Actions routed through Sentinel are limited to this task. Important changes still need your approval."
                : "Create a task to choose what your agent can do."}
            </p>
            {activeContract ? (
              <div className="mt-5 flex items-center gap-4">
                <Button asChild variant="secondary" size="sm">
                  <Link href="/tasks">Create replacement task</Link>
                </Button>
                <Link
                  href="/settings"
                  className="link-draw text-[11px] text-[var(--subtext)] hover:text-[var(--ink)]"
                >
                  Manage preferences
                </Link>
              </div>
            ) : null}
        </section>

        <section className="xl:col-start-1 xl:row-start-2">
            <h2 className={sectionLabelClass}>Workspace setup</h2>
            <div className="mt-3 divide-y divide-[var(--line)]">
              <SetupRow
                label="Approval preference"
                detail="Ask before important changes"
                value="Always ask"
              />
              <SetupRow
                label="Workspace access"
                detail="The agent stays inside the selected project"
                value={status?.runtime.workspace.status === "ready" ? "Ready" : "Needs attention"}
              />
              <SetupRow
                label="Protected execution"
                detail="Approved work runs in the restricted executor"
                value={status?.runtime.docker.status === "ready" ? "Ready" : "Unavailable"}
              />
              <SetupRow
                label="Decision policy"
                detail="Deterministic safety rules remain in control"
                value={status?.runtime.rules.status === "ready" ? "Ready" : "Unavailable"}
              />
            </div>
        </section>

        <section className="xl:col-start-2 xl:row-start-1">
          {approvalCount > 0 ? (
            <div className="rounded-[5px] border-2 border-black bg-[var(--main-soft)] p-5 shadow-[4px_4px_0_0_#000]">
              <p className={sectionLabelClass}>
                Needs your attention
              </p>
              <h2 className="mt-2 text-[17px] font-semibold">
                {approvalCount === 1
                  ? "One change is waiting"
                  : `${approvalCount} changes are waiting`}
              </h2>
              <p className="mt-1 text-[11px] leading-5 text-[var(--subtext)]">
                Review what the agent wants to do before anything happens.
              </p>
              <Button asChild size="sm" className="mt-4">
                <Link href="/approvals">Review change</Link>
              </Button>
            </div>
          ) : (
            <div>
              <p className={sectionLabelClass}>Attention</p>
              <h2 className="mt-2 text-[15px] font-semibold">
                Nothing needs review
              </h2>
              <p className="mt-1 text-[11px] leading-5 text-[var(--subtext)]">
                New approval requests will appear here.
              </p>
            </div>
          )}
        </section>

        <aside className="xl:col-start-2 xl:row-start-2">
          <section>
            <p className={sectionLabelClass}>Manage</p>
            <div className="mt-3 divide-y divide-[var(--line)]">
              <ManageRow
                label="Connections"
                detail="Manage agents and connected accounts"
                href="/settings"
              />
              <ManageRow
                label="Activity"
                detail="Review recent decisions and changes"
                href="/audit"
              />
            </div>
          </section>

          <section className="mt-10">
            <h2 className={sectionLabelClass}>Current environment</h2>
            <dl className="mt-3 divide-y divide-[var(--line)]">
              <Fact
                label="Workspace"
                value={status?.workspace.name ?? "Unavailable"}
              />
              <Fact
                label="Mode"
                value={status?.runtime.demo_mode ? "Demo workspace" : "Local workspace"}
              />
              <Fact label="Learning model" value="Off" />
            </dl>
          </section>
        </aside>
      </div>
    </div>
  );
}

function SetupRow({
  label,
  detail,
  value,
}: {
  label: string;
  detail: string;
  value: string;
}) {
  return (
    <div className="flex min-h-14 items-center justify-between gap-6">
      <div>
        <p className="text-[12px] font-medium">{label}</p>
        <p className="mt-0.5 text-[10px] text-[var(--subtext)]">{detail}</p>
      </div>
      <span className="shrink-0 text-[11px] text-[var(--subtext)]">{value}</span>
    </div>
  );
}

function ManageRow({
  label,
  detail,
  href,
}: {
  label: string;
  detail: string;
  href: string;
}) {
  return (
    <div className="flex min-h-14 items-center justify-between gap-6">
      <div>
        <p className="text-[12px] font-medium">{label}</p>
        <p className="mt-0.5 text-[10px] text-[var(--subtext)]">{detail}</p>
      </div>
      <Link
        href={href}
        className="link-draw text-[11px] text-[var(--subtext)] hover:text-[var(--ink)]"
      >
        Open
      </Link>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-5 py-3 text-[11px]">
      <dt className="text-[var(--subtext)]">{label}</dt>
      <dd className="font-medium">{value}</dd>
    </div>
  );
}
