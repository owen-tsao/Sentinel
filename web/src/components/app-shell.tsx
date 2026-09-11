"use client";

import {
  ChevronLeft,
  ClipboardCheck,
  FileClock,
  LayoutDashboard,
  ListTodo,
  Settings,
  ShieldCheck,
} from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, type ReactNode } from "react";

import { ControlProvider, useControl } from "@/components/control-provider";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { StatusDot } from "@/components/ui/layout";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { API_HOST } from "@/lib/control-api";
import { cn } from "@/lib/utils";

const apiHost = API_HOST;

const navigation = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/tasks", label: "Tasks", icon: ListTodo },
  { href: "/approvals", label: "Approvals", icon: ClipboardCheck },
  { href: "/audit", label: "Activity", icon: FileClock },
  { href: "/settings", label: "Settings", icon: Settings },
];

function ShellContent({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const {
    connection,
    status,
    activeContract,
    approvalCount,
    message,
    refresh,
  } = useControl();
  const connected = connection === "connected";

  return (
    <div
      className={cn(
        "min-h-screen bg-[var(--canvas)] text-[var(--ink)] lg:grid lg:grid-cols-[220px_minmax(0,1fr)] lg:transition-[grid-template-columns] lg:duration-200",
        collapsed && "lg:grid-cols-[72px_minmax(0,1fr)]",
      )}
    >
      <aside className="sticky top-0 hidden h-screen overflow-hidden border-r-[1.5px] border-[var(--outline)] lg:flex lg:flex-col">
        <div className="flex h-[52px] shrink-0 items-center gap-2.5 px-5">
          <Link
            href="/"
            aria-label="Sentinel overview"
            className="grid size-[26px] shrink-0 place-items-center rounded-[7px] border-[1.5px] border-[var(--outline)] bg-white outline-none focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2"
          >
              <Image
                src="/sentinel-mark.svg"
                alt=""
                width={14}
                height={16}
                priority
              />
          </Link>
          {!collapsed ? (
            <div className="whitespace-nowrap leading-tight">
              <div className="text-[13px] font-semibold tracking-[-0.01em]">
                Sentinel
              </div>
              <div className="text-[11px] text-[var(--subtext)]">
                Control center
              </div>
            </div>
          ) : null}
        </div>

        <nav aria-label="Primary" className="flex flex-col gap-0.5 px-3 pt-2">
          {navigation.map(({ href, label, icon: Icon }) => {
            const active =
              pathname === href || (href !== "/" && pathname.startsWith(href));
            return (
              <Link
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                aria-label={collapsed ? label : undefined}
                className={cn(
                  "relative flex h-8 items-center gap-2.5 rounded-[7px] border-[1.5px] border-transparent px-2.5 text-[13px] font-medium outline-none transition-colors focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2",
                  collapsed && "justify-center px-0",
                  active
                    ? "border-[var(--outline)] bg-white text-[var(--ink)]"
                    : "text-[var(--subtext)] hover:bg-[var(--hover)] hover:text-[var(--ink)]",
                )}
              >
                <Icon aria-hidden="true" size={15} strokeWidth={1.6} />
                {!collapsed ? <span>{label}</span> : null}
                {!collapsed && label === "Approvals" && approvalCount > 0 ? (
                  <span className="ml-auto rounded-full bg-[var(--ink)] px-1.5 font-mono text-[11px] leading-[17px] text-white">
                    {approvalCount}
                  </span>
                ) : null}
              </Link>
            );
          })}
        </nav>

        <div className="mt-auto flex items-center justify-between gap-2 px-5 pb-4">
          {!collapsed ? (
            <span className="font-mono text-[11px] text-[var(--faint)]">
              {apiHost} · local
            </span>
          ) : null}
          <button
            type="button"
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
            className="grid size-7 place-items-center rounded-[6px] text-[var(--faint)] outline-none transition-colors hover:bg-[var(--hover)] hover:text-[var(--ink)] focus-visible:ring-2 focus-visible:ring-black"
            onClick={() => setCollapsed((current) => !current)}
          >
            <ChevronLeft
              aria-hidden="true"
              size={14}
              className={cn("transition-transform", collapsed && "rotate-180")}
            />
          </button>
        </div>
      </aside>

      <div className="min-w-0">
        <header className="border-b-[1.5px] border-[var(--outline)]">
          <div className="flex h-[52px] items-center gap-4 px-5 lg:px-7">
            <Link
              href="/"
              aria-label="Sentinel overview"
              className="grid size-[26px] shrink-0 place-items-center rounded-[7px] border-[1.5px] border-[var(--outline)] bg-white outline-none focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2 lg:hidden"
            >
              <Image
                src="/sentinel-mark.svg"
                alt=""
                width={14}
                height={16}
                priority
              />
            </Link>
            <div className="flex min-w-0 items-center gap-4">
              <p className="truncate text-[13px] font-semibold tracking-[-0.01em]">
                {status?.workspace.name ?? "Personal workspace"}
              </p>
              <StatusDot
                tone={
                  !connected
                    ? "muted"
                    : status?.mandatory_agent_connected
                      ? "ok"
                      : "warn"
                }
                className="text-[12px] text-[var(--subtext)]"
              >
                {connected
                  ? status?.mandatory_agent_connected
                    ? "Agent connected"
                    : "Agent enforcement advisory"
                  : message}
              </StatusDot>
            </div>
            <div className="ml-auto flex items-center gap-3">
              {activeContract ? (
                <span className="hidden font-mono text-[12px] text-[var(--subtext)] sm:inline">
                  Task active · expires {formatClock(activeContract.contract.expires_at)}
                </span>
              ) : pathname !== "/" ? (
                <Link
                  href="/tasks"
                  className="link-draw text-[12px] text-[var(--subtext)] hover:text-[var(--ink)]"
                >
                  Create task
                </Link>
              ) : null}
            </div>
          </div>

          <nav
            aria-label="Mobile primary"
            className="flex overflow-x-auto border-t border-[var(--line)] px-3 py-2 lg:hidden"
          >
            {navigation.map(({ href, label, icon: Icon }) => {
              const active =
                pathname === href ||
                (href !== "/" && pathname.startsWith(href));
              return (
                <Link
                  key={href}
                  href={href}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "flex h-8 shrink-0 items-center gap-1.5 rounded-[7px] border-[1.5px] border-transparent px-2.5 text-[12px] font-medium",
                    active
                      ? "border-[var(--outline)] bg-white text-[var(--ink)]"
                      : "text-[var(--subtext)]",
                  )}
                >
                  <Icon aria-hidden="true" size={14} strokeWidth={1.5} />
                  {label}
                  {label === "Approvals" && approvalCount > 0 ? (
                    <Badge variant="secondary">{approvalCount}</Badge>
                  ) : null}
                </Link>
              );
            })}
          </nav>
        </header>

        <main className="w-full max-w-[1280px] px-5 py-5 lg:px-7">
          {connected ? (
            children
          ) : connection === "connecting" ? (
            <LoadingState />
          ) : (
            <ConnectionState
              connection={connection}
              message={message}
              onRetry={() => void refresh()}
            />
          )}
        </main>
      </div>
    </div>
  );
}

function formatClock(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function LoadingState() {
  return (
    <div aria-busy="true" aria-label="Loading local control state">
      <Skeleton className="h-7 w-44" />
      <Skeleton className="mt-2 h-4 w-80 max-w-full" />
      <div className="mt-8 flex flex-col gap-3">
        {[0, 1, 2].map((item) => (
          <Skeleton key={item} className="h-16 rounded-[5px]" />
        ))}
      </div>
    </div>
  );
}

function ConnectionState({
  connection,
  message,
  onRetry,
}: {
  connection: string;
  message: string;
  onRetry: () => void;
}) {
  return (
    <div className="grid min-h-[calc(100vh-52px-40px)] place-items-center">
      <Empty className="w-full max-w-lg flex-none">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <ShieldCheck aria-hidden="true" />
          </EmptyMedia>
          <EmptyTitle>{message}</EmptyTitle>
          <EmptyDescription>
            {connection === "pairing_required"
              ? "Launch Sentinel again and open the fresh local pairing link. Pairing links work once."
              : "Sentinel will not use an unprotected connection."}
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <Button variant="secondary" onClick={onRetry}>Retry connection</Button>
        </EmptyContent>
      </Empty>
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <ControlProvider>
      <ShellContent>{children}</ShellContent>
    </ControlProvider>
  );
}
