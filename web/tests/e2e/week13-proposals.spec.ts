import { expect, test, type Page } from "@playwright/test";

const apiOrigin = "http://127.0.0.1:8000";

const proposal = {
  draft_id: "draft-w13-1",
  state: "pending",
  source: "agent_mcp",
  operation: "write",
  exact_targets: ["SPIKE-1", "SPIKE-2"],
  environment: "sandbox",
  allowed_effects: ["read", "write"],
  task_duration_minutes: 30,
  objective: "Add notes to fixture issues SPIKE-1, SPIKE-2 through the Sentinel MCP tools.",
  proposal_number: 1,
  created_at: new Date(Date.now() - 2 * 60_000).toISOString(),
  proposal_expires_at: new Date(Date.now() + 13 * 60_000).toISOString(),
  replaces_active_task: false,
  resolution: null,
  resolved_at: null,
  superseded_by: null,
  confirmed_contract_id: null,
  confirmed_task_id: null,
};

const confirmedAuthority = {
  contract_id: "contract-w13",
  task_id: "task-w13",
  session_id: "session-1",
  version: 1,
  authority_epoch: 1,
  status: "active",
  authorization_source: "protected_local_ui",
  authorization_reference: "task-proposal:draft-w13-1",
  preflight_status: "complete",
  created_at: "2026-09-09T21:00:00Z",
  updated_at: "2026-09-09T21:00:00Z",
  expires_at: "2027-09-09T22:00:00Z",
  contract: {
    objective: proposal.objective,
    allowed_operations: ["read", "write"],
    allowed_tools: ["sentinel_issue_read", "sentinel_issue_add_note"],
    exact_targets: ["SPIKE-1", "SPIKE-2"],
    environment: "sandbox",
    maximum_scope: "exact",
    expected_side_effects: ["One internal note on a fixture issue."],
    allowed_effects: ["read", "write"],
    forbidden_operations: ["delete", "network", "credential_access"],
    forbidden_effects: ["No deletion, network, or credential access."],
    forbidden_effect_codes: ["delete", "network", "credential_access"],
    rollback_plan: "Notes are disposable fixture data.",
    dry_run_required: false,
  },
};

type State = {
  proposal: typeof proposal | null;
  authority: typeof confirmedAuthority | null;
};

async function installRoutes(page: Page, state: State) {
  await page.route(`${apiOrigin}/control/status`, (route) =>
    route.fulfill({
      json: {
        paired: true,
        supervision_session_id: "session-1",
        session_absolute_expires_at: "2027-09-09T22:00:00Z",
        workspace: {
          name: "sample-repository",
          canonical_path: "/tmp/sample-repository",
          identity_sha256: "a".repeat(64),
        },
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
    route.fulfill({ json: { approvals: [] } }),
  );
  await page.route(`${apiOrigin}/control/proposals/pending`, (route) =>
    route.fulfill({ json: { proposal: state.proposal, recent: [] } }),
  );
}

test("overview shows the proposed task with every fact and grants nothing until activated", async ({
  page,
}) => {
  await installRoutes(page, { proposal, authority: null });
  await page.goto("/");

  const card = page.getByRole("region", { name: proposal.objective });
  await expect(card).toBeVisible();
  await expect(card.getByText("Proposed task")).toBeVisible();
  await expect(card.getByText(/Proposed by the agent 2 minutes ago; Sentinel has not verified/)).toBeVisible();
  await expect(card.getByText("Read and add notes")).toBeVisible();
  await expect(card.getByText("SPIKE-1", { exact: true })).toBeVisible();
  await expect(card.getByText("SPIKE-2", { exact: true })).toBeVisible();
  await expect(card.getByText("Issues (2)")).toBeVisible();
  await expect(card.getByText("sandbox", { exact: true })).toBeVisible();
  await expect(card.getByText("read, write")).toBeVisible();
  await expect(card.getByText("30 minutes after activation")).toBeVisible();
  await expect(card.getByText(/grants nothing until you activate it/)).toBeVisible();
  await expect(card.getByRole("button", { name: "Activate" })).toBeEnabled();
  await expect(card.getByRole("button", { name: "Adjust in full form" })).toBeEnabled();
  await expect(card.getByRole("button", { name: "Dismiss" })).toBeEnabled();
  await expect(page.getByText("Activating replaces your current task")).toHaveCount(0);
  // Nothing is active yet: the proposal takes the focus slot and the overview
  // must not claim a current task anywhere.
  await expect(page.getByText("Current task")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Create replacement task" })).toHaveCount(0);
});

test("one click activates the proposal by draft ID only and the card disappears", async ({
  page,
}) => {
  const state: State = { proposal, authority: null };
  await installRoutes(page, state);
  let confirmBody: unknown = null;
  await page.route(`${apiOrigin}/control/proposals/draft-w13-1/confirm`, (route) => {
    confirmBody = route.request().postDataJSON();
    state.proposal = null;
    state.authority = confirmedAuthority;
    return route.fulfill({
      json: { draft_id: "draft-w13-1", state: "confirmed", active_contract: confirmedAuthority },
    });
  });
  await page.goto("/");

  await page.getByRole("button", { name: "Activate" }).click();

  // The proposal is gone and the same objective now reads as the current task.
  await expect(page.getByText("Proposed task")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Activate" })).toHaveCount(0);
  const focus = page.getByRole("region", { name: proposal.objective });
  await expect(focus).toContainText("Current task");
  expect(confirmBody).toEqual({ expected_active_task_id: null });
});

test("a stale confirmation explains itself instead of activating", async ({ page }) => {
  await installRoutes(page, { proposal, authority: null });
  await page.route(`${apiOrigin}/control/proposals/draft-w13-1/confirm`, (route) =>
    route.fulfill({
      status: 409,
      json: {
        detail: {
          reason_code: "proposal:superseded",
          reason: "This proposal was replaced by a newer one.",
        },
      },
    }),
  );
  await page.goto("/");

  await page.getByRole("button", { name: "Activate" }).click();

  await expect(page.getByRole("alert").filter({ hasText: /proposal/ })).toContainText("no longer current");
});

test("replacing an active task is stated before the click and guarded on the wire", async ({
  page,
}) => {
  const activeBefore = { ...confirmedAuthority, task_id: "task-old", contract_id: "contract-old" };
  await installRoutes(page, {
    proposal: { ...proposal, replaces_active_task: true },
    authority: activeBefore,
  });
  let confirmBody: unknown = null;
  await page.route(`${apiOrigin}/control/proposals/draft-w13-1/confirm`, (route) => {
    confirmBody = route.request().postDataJSON();
    return route.fulfill({
      json: { draft_id: "draft-w13-1", state: "confirmed", active_contract: confirmedAuthority },
    });
  });
  await page.goto("/");

  await expect(page.getByText("Activating replaces your current task; its pending approvals will be cleared.")).toBeVisible();
  await page.getByRole("button", { name: "Activate" }).click();

  await expect.poll(() => confirmBody).toEqual({ expected_active_task_id: "task-old" });
});

test("dismiss retires the draft without touching authority", async ({ page }) => {
  const state: State = { proposal, authority: null };
  await installRoutes(page, state);
  let authorityMutations = 0;
  await page.route(`${apiOrigin}/control/contracts/**`, (route) => {
    authorityMutations += 1;
    return route.fulfill({ status: 500, json: {} });
  });
  await page.route(`${apiOrigin}/control/proposals/draft-w13-1/dismiss`, (route) => {
    state.proposal = null;
    return route.fulfill({ json: { draft_id: "draft-w13-1", state: "dismissed" } });
  });
  await page.goto("/");

  await page.getByRole("button", { name: "Dismiss" }).click();

  await expect(page.getByRole("region", { name: proposal.objective })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "No task is active" })).toBeVisible();
  expect(authorityMutations).toBe(0);
});

test("adjust in full form consumes the draft and prefills the reviewed task form", async ({
  page,
}) => {
  const state: State = { proposal, authority: null };
  await installRoutes(page, state);
  await page.route(`${apiOrigin}/control/proposals/draft-w13-1/adjust`, (route) => {
    state.proposal = null;
    return route.fulfill({
      json: {
        draft_id: "draft-w13-1",
        state: "superseded",
        raw_prompt: proposal.objective,
        accepted_contract: {
          operation: "write",
          exact_targets: ["SPIKE-1", "SPIKE-2"],
          environment: "sandbox",
          expected_side_effects: ["One internal note per approved write."],
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
        },
      },
    });
  });
  await page.route(`${apiOrigin}/control/contracts/draft`, (route) =>
    route.fulfill({
      json: {
        prompt_sha256: "c".repeat(64),
        suggestions: [],
        questions: [],
        proposed_contract: null,
      },
    }),
  );
  await page.goto("/");

  await page.getByRole("button", { name: "Adjust in full form" }).click();

  await expect(page).toHaveURL(/\/tasks$/);
  await expect(page.getByText(/Prefilled from the agent's proposal/)).toBeVisible();
  await expect(page.getByText("Allowed fixture issues")).toBeVisible();
  // Targets are chips now, each removable on its own.
  await expect(page.getByRole("button", { name: "Remove SPIKE-1" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Remove SPIKE-2" })).toBeVisible();
  await expect(page.getByRole("region", { name: proposal.objective })).toHaveCount(0);
});
