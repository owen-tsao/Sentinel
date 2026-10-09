import { expect, test, type Page } from "@playwright/test";

/**
 * Week 14, revised: no count anywhere. The person sees the rule in words
 * (reads free; notes inside the task run; anything outside is blocked) and
 * the idle ticket says what standing reads change. The form offers no
 * budget field, and the confirm body carries no count.
 */

const apiOrigin = "http://127.0.0.1:8000";

const ceiling = (overrides: Record<string, unknown> = {}) => ({
  adapter_kind: "cursor_mcp",
  tool_family: "sentinel_issue_fixture",
  policy_sha256: "b".repeat(64),
  expires_at: "2027-09-11T05:00:00Z",
  expired: false,
  max_write_budget: 50,
  standing_read: false,
  ...overrides,
});

const integration = (overrides: Record<string, unknown> = {}) => ({
  gateway: { status: "ready", detail: "MCP gateway bound." },
  hooks: { status: "ready", detail: "Hooks cover events." },
  sandbox: { status: "unavailable", detail: "Host setting." },
  ceiling: ceiling(overrides),
  agent: {
    host: "cursor",
    status: "connected",
    last_seen_at: "2026-09-11T21:30:00Z",
    last_tool: "sentinel_issue_read",
    last_verdict: "allow",
    mediated_calls: 3,
    rejected_calls: 0,
    adapter_session_expires_at: "2027-09-11T05:00:00Z",
  },
  coverage: [],
});

const contractWith = (
  limit: number,
  operations: string[] = ["read", "write"],
  tools: string[] = ["sentinel_issue_read", "sentinel_issue_add_note"],
) => ({
  contract_id: "contract-w14",
  task_id: "task-w14",
  session_id: "session-1",
  version: 1,
  authority_epoch: 1,
  status: "active",
  authorization_source: "protected_local_ui",
  authorization_reference: "task-proposal:draft-w14",
  preflight_status: "complete",
  created_at: "2026-09-11T21:00:00Z",
  updated_at: "2026-09-11T21:00:00Z",
  expires_at: "2027-09-11T22:00:00Z",
  contract: {
    objective: "Add notes to fixture issues SPIKE-1, SPIKE-2 through the Sentinel MCP tools.",
    allowed_operations: operations,
    allowed_tools: tools,
    exact_targets: ["SPIKE-1", "SPIKE-2"],
    environment: "sandbox",
    maximum_scope: "exact",
    expected_side_effects: ["Notes on fixture issues."],
    allowed_effects: operations,
    forbidden_operations: ["delete", "network", "credential_access"],
    forbidden_effects: ["No deletion, network, or credential access."],
    forbidden_effect_codes: ["delete", "network", "credential_access"],
    rollback_plan: "Notes are disposable fixture data.",
    dry_run_required: false,
    write_budget: limit,
  },
});

const proposalWith = (operation: "read" | "write" = "write") => ({
  draft_id: "draft-w14",
  state: "pending",
  source: "agent_mcp",
  operation,
  exact_targets: ["SPIKE-1", "SPIKE-2"],
  environment: "sandbox",
  allowed_effects: operation === "write" ? ["read", "write"] : ["read"],
  task_duration_minutes: 30,
  write_budget: operation === "write" ? 50 : 0,
  objective: "Add notes to fixture issues SPIKE-1, SPIKE-2 through the Sentinel MCP tools.",
  proposal_number: 1,
  created_at: new Date(Date.now() - 60_000).toISOString(),
  proposal_expires_at: new Date(Date.now() + 14 * 60_000).toISOString(),
  replaces_active_task: false,
  resolution: null,
  resolved_at: null,
  superseded_by: null,
  confirmed_contract_id: null,
  confirmed_task_id: null,
});

async function installRoutes(
  page: Page,
  state: {
    authority?: ReturnType<typeof contractWith> | null;
    proposal?: ReturnType<typeof proposalWith> | null;
    ceiling?: Record<string, unknown> | null;
  },
) {
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
        mandatory_agent_connected: state.ceiling !== null,
        connection_message: "Cursor MCP shim connected.",
        integration: state.ceiling === null ? null : integration(state.ceiling ?? {}),
      },
    }),
  );
  await page.route(`${apiOrigin}/control/authority/active`, (route) =>
    route.fulfill({ json: { active_contract: state.authority ?? null } }),
  );
  await page.route(`${apiOrigin}/control/approvals`, (route) => route.fulfill({ json: { approvals: [] } }));
  await page.route(`${apiOrigin}/control/proposals/pending`, (route) =>
    route.fulfill({ json: { proposal: state.proposal ?? null, recent: [] } }),
  );
  await page.route(`${apiOrigin}/control/audit**`, (route) => route.fulfill({ json: { events: [] } }));
  await page.route(`${apiOrigin}/control/targets`, (route) =>
    route.fulfill({ json: { workspace_root: "/tmp/sample-repository", suggestions: [], fixture_issues: ["SPIKE-1", "SPIKE-2"] } }),
  );
}

test("the idle ticket says reads are allowed only when the ceiling declares standing reads", async ({ page }) => {
  await installRoutes(page, { ceiling: { standing_read: true } });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "No task is active" })).toBeVisible();
  await expect(page.getByText(/Your agent can read fixture issues, but every write stays blocked/)).toBeVisible();

  await page.unroute(`${apiOrigin}/control/status`);
  await installRoutes(page, { ceiling: { standing_read: false } });
  await page.reload();
  await expect(page.getByText(/Sentinel-guarded tools stay blocked until you activate a task/)).toBeVisible();
});

test("the active ticket states the rule in words and never shows a count", async ({ page }) => {
  await installRoutes(page, { authority: contractWith(50) });
  await page.goto("/");
  const ticket = page.getByRole("region", { name: contractWith(50).contract.objective });
  await expect(ticket.getByText(/notes inside this task run without asking/)).toBeVisible();
  await expect(ticket.getByText(/Anything outside it is blocked/)).toBeVisible();
  await expect(page.getByText("Notes without asking")).toHaveCount(0);
  await expect(page.getByText(/Up to \d+/)).toHaveCount(0);

  // A shell write task still pauses per write; the fixture wording must not leak onto it.
  await page.unroute(`${apiOrigin}/control/authority/active`);
  await page.route(`${apiOrigin}/control/authority/active`, (route) =>
    route.fulfill({ json: { active_contract: contractWith(0, ["read", "write"], ["shell"]) } }),
  );
  await page.reload();
  await expect(ticket.getByText("Reads run freely; each write pauses for your approval.")).toBeVisible();

  await page.unroute(`${apiOrigin}/control/authority/active`);
  await page.route(`${apiOrigin}/control/authority/active`, (route) =>
    route.fulfill({ json: { active_contract: contractWith(0, ["read"], ["sentinel_issue_read"]) } }),
  );
  await page.reload();
  await expect(ticket.getByText("Reads run freely; this task cannot write.")).toBeVisible();
});

test("the proposal card shows the grant without a count", async ({ page }) => {
  await installRoutes(page, { proposal: proposalWith("write") });
  await page.goto("/");
  const card = page.getByRole("region", { name: proposalWith().objective });
  await expect(card.getByText("Read and add notes")).toBeVisible();
  await expect(card.getByText("SPIKE-1", { exact: true })).toBeVisible();
  await expect(page.getByText("Notes without asking")).toHaveCount(0);
  await expect(page.getByText(/Up to \d+/)).toHaveCount(0);
});

test("the full form offers no budget field and sends no count on confirm", async ({ page }) => {
  await installRoutes(page, { proposal: proposalWith("write"), ceiling: {} });
  await page.route(`${apiOrigin}/control/proposals/draft-w14/adjust`, (route) =>
    route.fulfill({
      json: {
        draft_id: "draft-w14",
        state: "superseded",
        raw_prompt: proposalWith().objective,
        accepted_contract: {
          operation: "write",
          exact_targets: ["SPIKE-1", "SPIKE-2"],
          environment: "sandbox",
          expected_side_effects: ["Internal notes on the listed fixture issues, added within the task."],
          allowed_effects: ["read", "write"],
          forbidden_operations: ["delete", "network", "credential_access"],
          forbidden_effects: ["No deletion, network, or credential access."],
          forbidden_effect_codes: ["delete", "network", "credential_access"],
          rollback_plan: "Notes are disposable fixture data.",
          dry_run_required: false,
          rollback_required: false,
          transaction_required: false,
          backup_required: false,
          expires_in_minutes: 30,
          tool_family: "sentinel_issue_fixture",
          write_budget: 50,
        },
      },
    }),
  );
  const draftBodies: Array<Record<string, unknown>> = [];
  await page.route(`${apiOrigin}/control/contracts/draft`, (route) => {
    const body = route.request().postDataJSON();
    draftBodies.push(body);
    return route.fulfill({
      json: {
        prompt_sha256: "c".repeat(64),
        suggestions: [],
        questions: [],
        proposed_contract: body.accepted_contract ? { ...contractWith(50), status: "proposed" } : null,
      },
    });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Adjust in full form" }).click();
  await expect(page).toHaveURL(/\/tasks$/);

  await expect(page.getByLabel("Notes without asking")).toHaveCount(0);
  await expect(page.getByText(/Notes on these issues run inside the task/)).toBeVisible();
  const ticket = page.getByRole("region", { name: /Task contract|Write/ }).first();
  await expect(ticket.getByText(/notes inside this task run without asking/)).toBeVisible();

  await page.getByRole("button", { name: "Confirm task settings" }).click();
  await expect.poll(() => draftBodies.length).toBeGreaterThanOrEqual(2);
  const confirmBody = draftBodies.at(-1)!;
  expect(confirmBody.accepted_contract).not.toHaveProperty("write_budget");
  await expect(page.getByText("Confirmed. Nothing is granted until you activate it.")).toBeVisible();
});
