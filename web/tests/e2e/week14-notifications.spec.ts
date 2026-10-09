import { expect, test, type Page } from "@playwright/test";

/**
 * Week 14 notification spike, mocked. Headless Chromium has no system tray,
 * so the Notification API and the service worker are stubbed in the page and
 * the spec checks what the tab would have shown and, more importantly, that
 * a click can only ever act through the same protected route as the card.
 */

const apiOrigin = "http://127.0.0.1:8000";

const proposal = {
  draft_id: "draft-w14-1",
  state: "pending",
  source: "agent_mcp",
  operation: "write",
  exact_targets: ["SPIKE-1"],
  environment: "sandbox",
  allowed_effects: ["read", "write"],
  task_duration_minutes: 30,
  write_budget: 50,
  objective: "Add a note to fixture issue SPIKE-1 through the Sentinel MCP tools.",
  proposal_number: 1,
  created_at: new Date(Date.now() - 60_000).toISOString(),
  proposal_expires_at: new Date(Date.now() + 14 * 60_000).toISOString(),
  replaces_active_task: false,
  resolution: null,
  resolved_at: null,
  superseded_by: null,
  confirmed_contract_id: null,
  confirmed_task_id: null,
};

const authority = {
  contract_id: "contract-w14",
  task_id: "task-w14",
  session_id: "session-1",
  version: 1,
  authority_epoch: 1,
  status: "active",
  authorization_source: "protected_local_ui",
  authorization_reference: "task-proposal:draft-w14-1",
  preflight_status: "complete",
  created_at: "2026-09-11T21:00:00Z",
  updated_at: "2026-09-11T21:00:00Z",
  expires_at: "2027-09-11T22:00:00Z",
  contract: {
    objective: proposal.objective,
    allowed_operations: ["read", "write"],
    allowed_tools: ["sentinel_issue_read", "sentinel_issue_add_note"],
    exact_targets: ["SPIKE-1"],
    environment: "sandbox",
    maximum_scope: "exact",
    expected_side_effects: ["Internal notes on the listed fixture issues, added within the task."],
    allowed_effects: ["read", "write"],
    forbidden_operations: ["delete", "network", "credential_access"],
    forbidden_effects: ["No deletion, network, or credential access."],
    forbidden_effect_codes: ["delete", "network", "credential_access"],
    rollback_plan: "Notes are disposable fixture data.",
    dry_run_required: false,
    write_budget: 50,
  },
};

const noteApproval: {
  approval_id: string;
  attempt_id: string;
  operation: string;
  raw_command: string;
  targets: string[];
  effects: string[];
  workspace: string;
  task_id: string;
  contract_id: string;
  contract_version: number;
  authority_epoch: number;
  environment: string;
  reasons: string[];
  expires_at: string;
  family: string;
  tool: string | null;
  arguments: Record<string, unknown>;
} = {
  approval_id: "approval-w14-note",
  attempt_id: "attempt-w14-note",
  operation: "write",
  raw_command: "sentinel_issue_add_note SPIKE-1",
  targets: ["SPIKE-1"],
  effects: ["write"],
  workspace: "/tmp/sample-repository",
  task_id: "task-w14",
  contract_id: "contract-w14",
  contract_version: 1,
  authority_epoch: 1,
  environment: "sandbox",
  reasons: ["supervision:confirm_operation"],
  expires_at: "2027-09-11T22:00:00Z",
  family: "sentinel_issue_fixture",
  tool: "sentinel_issue_add_note",
  arguments: { issue_id: "SPIKE-1", body: "second note" },
};

type State = {
  proposal: typeof proposal | null;
  authority: typeof authority | null;
  approvals: Array<typeof noteApproval>;
};

type Shown = { via: "worker" | "plain"; title: string; body: string; actions: string[]; data: unknown };

async function installRoutes(page: Page, state: State) {
  await page.route(`${apiOrigin}/control/status`, (route) =>
    route.fulfill({
      json: {
        paired: true,
        supervision_session_id: "session-1",
        session_absolute_expires_at: "2027-09-11T22:00:00Z",
        workspace: { name: "sample-repository", canonical_path: "/tmp/sample-repository", identity_sha256: "a".repeat(64) },
        runtime: {
          backend: { status: "ready", detail: "FastAPI ready." },
          workspace: { status: "ready", detail: "Workspace reviewed." },
          docker: { status: "ready", detail: "Docker daemon ready." },
          rules: { status: "ready", detail: "Rules and audit ready." },
          demo_mode: false,
          sample_repository: null,
        },
        ml_status: "disabled",
        mandatory_agent_connected: true,
        connection_message: "Cursor MCP shim connected.",
        integration: null,
      },
    }),
  );
  await page.route(`${apiOrigin}/control/authority/active`, (route) =>
    route.fulfill({ json: { active_contract: state.authority } }),
  );
  await page.route(`${apiOrigin}/control/approvals`, (route) =>
    route.fulfill({ json: { approvals: state.approvals } }),
  );
  await page.route(`${apiOrigin}/control/proposals/pending`, (route) =>
    route.fulfill({ json: { proposal: state.proposal, recent: [] } }),
  );
  await page.route(`${apiOrigin}/control/audit**`, (route) => route.fulfill({ json: { events: [] } }));
}

/** Stub the browser surfaces the tab uses; `withActions` mimics Chromium vs Safari/Firefox. */
async function stubNotifications(page: Page, { withActions }: { withActions: boolean }) {
  await page.addInitScript(
    ({ withActions }) => {
      const shown: Shown[] = [];
      const win = window as unknown as Record<string, unknown>;
      win.__shown = shown;
      win.__permissionRequests = 0;
      window.localStorage.setItem("sentinel.notifications.v1", "on");
      document.hasFocus = () => false;

      class FakeNotification {
        static permission = "granted";
        static async requestPermission() {
          (win.__permissionRequests as number)++;
          return "granted";
        }
        onclick: (() => void) | null = null;
        constructor(title: string, options: { body?: string; data?: unknown } = {}) {
          shown.push({ via: "plain", title, body: options.body ?? "", actions: [], data: options.data });
          win.__lastPlain = this;
        }
        close() {}
      }
      if (withActions) {
        Object.defineProperty(FakeNotification.prototype, "actions", { get: () => [] });
      }
      win.Notification = FakeNotification;

      const bus = new EventTarget();
      const registration = {
        async showNotification(title: string, options: { body?: string; data?: unknown; actions?: Array<{ title: string }> }) {
          shown.push({
            via: "worker",
            title,
            body: options.body ?? "",
            actions: (options.actions ?? []).map((action) => action.title),
            data: options.data,
          });
        },
      };
      Object.defineProperty(navigator, "serviceWorker", {
        configurable: true,
        value: {
          register: async () => registration,
          addEventListener: (type: string, handler: EventListener) => bus.addEventListener(type, handler),
          removeEventListener: (type: string, handler: EventListener) => bus.removeEventListener(type, handler),
        },
      });
      win.__clickFromWorker = (data: unknown) => bus.dispatchEvent(new MessageEvent("message", { data }));
    },
    { withActions },
  );
}

const shown = (page: Page) => page.evaluate(() => (window as unknown as { __shown: Shown[] }).__shown);
const clickFromWorker = (page: Page, data: unknown) =>
  page.evaluate((payload) => (window as unknown as { __clickFromWorker: (d: unknown) => void }).__clickFromWorker(payload), data);

test("a proposal that appears on a later poll is announced with the exact grant, and the Activate action confirms through the protected route", async ({
  page,
}) => {
  const state: State = { proposal: null, authority: null, approvals: [] };
  await stubNotifications(page, { withActions: true });
  await installRoutes(page, state);
  let confirmBody: unknown = null;
  await page.route(`${apiOrigin}/control/proposals/${proposal.draft_id}/confirm`, (route) => {
    confirmBody = route.request().postDataJSON();
    state.proposal = null;
    state.authority = authority;
    route.fulfill({ json: { proposal: { ...proposal, state: "confirmed" }, active_contract: authority } });
  });

  await page.clock.install();
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "No task is active" })).toBeVisible();
  expect(await shown(page)).toEqual([]);

  state.proposal = proposal;
  await page.clock.runFor(15_000);
  await expect(page.getByRole("region", { name: proposal.objective })).toBeVisible();
  await expect.poll(() => shown(page)).toHaveLength(1);
  const [notice] = await shown(page);
  expect(notice.via).toBe("worker");
  expect(notice.title).toBe("Your agent proposed a task");
  expect(notice.body).toContain(proposal.objective);
  expect(notice.body).toContain("read and add notes · SPIKE-1 · 30 min");
  expect(notice.body).not.toMatch(/budget|without asking/);
  expect(notice.actions).toEqual(["Activate", "Open"]);
  expect(notice.data).toEqual({ kind: "proposal", id: proposal.draft_id, path: "/" });

  // Polling again must not re-announce the same proposal.
  await page.clock.runFor(15_000);
  expect(await shown(page)).toHaveLength(1);

  await clickFromWorker(page, { type: "sentinel:notification", action: "decide", kind: "proposal", id: proposal.draft_id, path: "/" });
  await expect.poll(() => confirmBody).toEqual({ expected_active_task_id: null });
  await expect(page.getByRole("heading", { name: proposal.objective })).toBeVisible();
  await expect(page.getByText("Notes without asking")).toHaveCount(0);
  await expect(page.getByText(/notes inside this task run without asking/)).toBeVisible();
});

test("without action-button support the notification is plain and a click only opens the card", async ({ page }) => {
  const state: State = { proposal: null, authority: null, approvals: [] };
  await stubNotifications(page, { withActions: false });
  await installRoutes(page, state);
  let confirmed = 0;
  await page.route(`${apiOrigin}/control/proposals/${proposal.draft_id}/confirm`, (route) => {
    confirmed++;
    route.fulfill({ status: 500, json: { detail: "must not be called" } });
  });

  await page.clock.install();
  await page.goto("/approvals");
  await expect(page.getByText("No changes need review")).toBeVisible();

  state.proposal = proposal;
  await page.clock.runFor(15_000);
  await expect.poll(() => shown(page)).toHaveLength(1);
  const [notice] = await shown(page);
  expect(notice.via).toBe("plain");
  expect(notice.actions).toEqual([]);

  await page.evaluate(() => (window as unknown as { __lastPlain: { onclick: () => void } }).__lastPlain.onclick());
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("region", { name: proposal.objective })).toBeVisible();
  await expect(page.getByRole("button", { name: "Activate" })).toBeVisible();
  expect(confirmed).toBe(0);
});

test("items already pending at load are not announced, and a forged click for an unknown item approves nothing", async ({
  page,
}) => {
  const state: State = { proposal, authority: null, approvals: [] };
  await stubNotifications(page, { withActions: true });
  await installRoutes(page, state);
  const posts: string[] = [];
  await page.route(`${apiOrigin}/control/proposals/*/confirm`, (route) => {
    posts.push(route.request().url());
    route.fulfill({ status: 404, json: { detail: { reason_code: "proposal:not_found", reason: "no" } } });
  });
  await page.route(`${apiOrigin}/control/approvals/*/approve`, (route) => {
    posts.push(route.request().url());
    route.fulfill({ status: 404, json: { detail: "no" } });
  });

  await page.clock.install();
  await page.goto("/");
  await expect(page.getByRole("region", { name: proposal.objective })).toBeVisible();
  expect(await shown(page)).toEqual([]);

  await clickFromWorker(page, { type: "sentinel:notification", action: "decide", kind: "proposal", id: "draft-someone-else", path: "/" });
  await expect(page.getByText("That item is no longer pending.")).toBeVisible();
  await clickFromWorker(page, { type: "sentinel:notification", action: "decide", kind: "approval", id: "approval-nope", path: "/approvals" });
  await expect(page.getByText("Notification click did not complete")).toBeVisible();
  await clickFromWorker(page, { type: "other", action: "decide", kind: "proposal", id: proposal.draft_id, path: "/" });
  expect(posts).toEqual([]);

  // The error describes the pending set at the time; once that set changes it goes away on its own.
  await page.getByRole("link", { name: "Overview" }).first().click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText("That item is no longer pending.")).toBeVisible();
  state.proposal = null;
  await page.clock.runFor(15_000);
  await expect(page.getByRole("heading", { name: "No task is active" })).toBeVisible();
  await expect(page.getByText("That item is no longer pending.")).toHaveCount(0);
});

test("a waiting note is announced with an Approve action that goes through the approval route; deletes are open-only", async ({
  page,
}) => {
  const state: State = { proposal: null, authority, approvals: [] };
  await stubNotifications(page, { withActions: true });
  await installRoutes(page, state);
  let approveBody: unknown = null;
  await page.route(`${apiOrigin}/control/approvals/${noteApproval.approval_id}/approve`, (route) => {
    approveBody = route.request().postDataJSON();
    state.approvals = [];
    route.fulfill({
      json: {
        approval_id: noteApproval.approval_id,
        status: "approved",
        retry: { verdict: "allow", reasons: ["mcp:approved_write_applied"] },
      },
    });
  });

  await page.clock.install();
  await page.goto("/");
  await expect(page.getByRole("heading", { name: proposal.objective })).toBeVisible();

  const deleteApproval = {
    ...noteApproval,
    approval_id: "approval-w14-delete",
    operation: "delete",
    tool: null,
    raw_command: "rm notes.txt",
    reasons: ["policy:delete_requires_typed_target"],
  };
  state.approvals = [noteApproval, deleteApproval];
  await page.clock.runFor(15_000);
  await expect.poll(() => shown(page)).toHaveLength(2);
  const notices = await shown(page);
  const note = notices.find((item) => (item.data as { id: string }).id === noteApproval.approval_id)!;
  const del = notices.find((item) => (item.data as { id: string }).id === deleteApproval.approval_id)!;
  expect(note.title).toBe("A write is waiting for your approval");
  expect(note.body).toBe("Add a note to SPIKE-1");
  expect(note.actions).toEqual(["Approve", "Open"]);
  expect(del.via).toBe("plain");
  expect(del.actions).toEqual([]);

  await clickFromWorker(page, {
    type: "sentinel:notification",
    action: "decide",
    kind: "approval",
    id: noteApproval.approval_id,
    path: "/approvals",
  });
  await expect.poll(() => approveBody).toEqual({ typed_target: null });
  await expect(page).toHaveURL(/\/approvals$/);
});
