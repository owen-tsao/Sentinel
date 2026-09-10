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
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

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
        "min-h-screen bg-white text-[var(--ink)] lg:grid lg:grid-cols-[220px_minmax(0,1fr)] lg:transition-[grid-template-columns] lg:duration-200",
        collapsed && "lg:grid-cols-[72px_minmax(0,1fr)]",
      )}
    >
      <aside className="sticky top-0 hidden h-screen overflow-hidden border-r border-[var(--line)] bg-white lg:flex lg:flex-col">
        <div className="flex h-16 shrink-0 items-center gap-2.5 border-b border-[var(--line)] px-[18px]">
          <Link
            href="/"
            aria-label="Sentinel overview"
            className="grid size-[30px] shrink-0 place-items-center rounded-[5px] border-2 border-black bg-white shadow-[2px_2px_0_0_#000] outline-none transition-[transform,box-shadow] hover:-translate-y-px hover:shadow-[3px_3px_0_0_#000] focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2 active:translate-x-px active:translate-y-px active:shadow-none"
          >
            <Image
              src="/sentinel-mark.svg"
              alt=""
              width={20}
              height={22}
              priority
            />
          </Link>
          {!collapsed ? (
            <div className="whitespace-nowrap">
              <div className="text-[13px] font-semibold tracking-[-0.01em]">
                Sentinel
              </div>
              <div className="text-[10px] text-[var(--subtext)]">
                Control center
              </div>
            </div>
          ) : null}
        </div>

        <nav aria-label="Primary" className="flex flex-col gap-1 p-3">
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
                  "relative flex h-10 items-center gap-2.5 rounded-[5px] px-3 text-[12px] font-medium outline-none transition-colors focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2",
                  collapsed && "justify-center px-0",
                  active
                    ? "bg-[var(--main-soft)] text-[var(--ink)] before:absolute before:left-0 before:h-5 before:w-[3px] before:rounded-full before:bg-[var(--main)]"
                    : "text-[var(--subtext)] hover:bg-[var(--main-faint)] hover:text-[var(--ink)]",
                )}
              >
                <Icon aria-hidden="true" size={15} strokeWidth={1.8} />
                {!collapsed ? <span>{label}</span> : null}
                {!collapsed && label === "Approvals" && approvalCount > 0 ? (
                  <Badge variant="secondary" className="ml-auto">
                    {approvalCount}
                  </Badge>
                ) : null}
              </Link>
            );
          })}
        </nav>

        <div className="mt-auto border-t border-[var(--line)] p-3">
          <button
            type="button"
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
            className="flex h-9 w-full items-center justify-center gap-2 rounded-[5px] text-[11px] text-[var(--subtext)] outline-none transition-colors hover:bg-[var(--main-faint)] hover:text-[var(--ink)] focus-visible:ring-2 focus-visible:ring-black"
            onClick={() => setCollapsed((current) => !current)}
          >
            <ChevronLeft
              aria-hidden="true"
              size={14}
              className={cn("transition-transform", collapsed && "rotate-180")}
            />
            {!collapsed ? <span>Collapse rail</span> : null}
          </button>
        </div>
      </aside>

      <div className="min-w-0">
        <header className="border-b border-[var(--line)] bg-white">
          <div className="flex min-h-16 items-center gap-3 px-5 lg:px-12">
            <Link
              href="/"
              aria-label="Sentinel overview"
              className="grid size-[30px] shrink-0 place-items-center rounded-[5px] border-2 border-black bg-white shadow-[2px_2px_0_0_#000] outline-none transition-[transform,box-shadow] hover:-translate-y-px hover:shadow-[3px_3px_0_0_#000] focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2 active:translate-x-px active:translate-y-px active:shadow-none lg:hidden"
            >
              <Image
                src="/sentinel-mark.svg"
                alt=""
                width={20}
                height={22}
                priority
              />
            </Link>
            <div className="min-w-0">
              <p className="truncate text-[12px] font-semibold">
                {status?.workspace.name ?? "Personal workspace"}
              </p>
              <p className="mt-0.5 text-[10px] text-[var(--subtext)]">
                {connected
                  ? status?.mandatory_agent_connected
                    ? `Mandatory agent connection active · ${status.connection_message}`
                    : `Agent enforcement is advisory · ${status?.connection_message ?? "No mandatory agent connected."}`
                  : message}
              </p>
            </div>
          </div>

          <div className="flex min-h-10 items-center justify-between gap-4 border-t border-[rgba(136,170,238,0.42)] bg-[var(--main-soft)] px-5 py-2 lg:px-12">
            <p className="min-w-0 truncate text-[11px]">
              <span className="font-semibold">
                {activeContract ? "Approval mode is on." : "No task is active."}
              </span>{" "}
              {activeContract
                ? "Sentinel will ask before making important changes."
                : "Create a task to choose what your agent can do."}
            </p>
            <Link
              href={activeContract ? "/settings" : "/tasks"}
              className="link-draw shrink-0 text-[11px] text-[var(--subtext)] hover:text-[var(--ink)]"
            >
              {activeContract ? "Manage" : "Create task"}
            </Link>
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
                    "flex h-8 shrink-0 items-center gap-1.5 rounded-[5px] px-2.5 text-[11px] font-medium",
                    active
                      ? "bg-[var(--main-soft)] text-[var(--ink)]"
                      : "text-[var(--subtext)]",
                  )}
                >
                  <Icon aria-hidden="true" size={13} />
                  {label}
                  {label === "Approvals" && approvalCount > 0 ? (
                    <Badge variant="secondary">{approvalCount}</Badge>
                  ) : null}
                </Link>
              );
            })}
          </nav>
        </header>

        <main className="mx-auto w-full max-w-[1220px] px-5 py-9 lg:px-12 lg:py-11">
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
    <Empty className="mx-auto mt-20 max-w-lg">
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
        <Button onClick={onRetry}>Retry connection</Button>
      </EmptyContent>
    </Empty>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <ControlProvider>
      <ShellContent>{children}</ShellContent>
    </ControlProvider>
  );
}
