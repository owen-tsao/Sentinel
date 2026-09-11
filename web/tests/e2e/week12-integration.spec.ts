import { expect, test, type Page } from "@playwright/test";

const apiOrigin = "http://127.0.0.1:8000";

const fixtureAuthority = {
  contract_id: "contract-mcp",
  task_id: "task-mcp",
  session_id: "session-1",
  version: 1,
  authority_epoch: 1,
  status: "active",
  authorization_source: "protected_local_ui",
  authorization_reference: "event-1",
  preflight_status: "complete",
  created_at: "2026-09-09T21:00:00Z",
  updated_at: "2026-09-09T21:00:00Z",
  expires_at: "2027-09-09T22:00:00Z",
  contract: {
    objective: "Read fixture issues and add one reviewed note.",
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

const integration = {
  gateway: {
    status: "ready",
    detail: "MCP gateway is bound to the startup ceiling and required audit storage.",
  },
  hooks: {
    status: "ready",
    detail: "Sentinel fail-closed hooks cover read, edit, shell, and MCP events.",
  },
  sandbox: {
    status: "unavailable",
    detail: "Cursor's agent sandbox is a host setting Sentinel cannot read.",
  },
  ceiling: {
    adapter_kind: "cursor_mcp",
    tool_family: "sentinel_issue_fixture",
    policy_sha256: "b".repeat(64),
    expires_at: "2026-09-10T05:00:00Z",
    expired: false,
  },
  agent: {
    host: "cursor",
    status: "connected",
    last_seen_at: "2026-09-09T21:30:00Z",
    last_tool: "sentinel_issue_read",
    last_verdict: "allow",
    mediated_calls: 3,
    rejected_calls: 1,
    adapter_session_expires_at: "2026-09-10T05:00:00Z",
  },
  coverage: [
    {
      family: "sentinel_issue_fixture",
      status: "mandatory",
      basis: "Every effect passed through Sentinel; fail closed when unavailable.",
      conditions: ["Cursor agent sandbox enabled"],
      known_bypasses: ["same-user agent can read Sentinel state (no effect possible)"],
    },
    {
      family: "shell",
      status: "advisory",
      basis: "Hooks can deny by command text but cannot redirect execution.",
      conditions: [],
      known_bypasses: [],
    },
    {
      family: "browser",
      status: "unsupported",
      basis: "Hook coverage of the browser tool is untested.",
      conditions: [],
      known_bypasses: [],
    },
  ],
};

const mcpApproval = {
  approval_id: "approval-mcp-1",
  attempt_id: "attempt-mcp-1",
  operation: "write",
  raw_command: 'sentinel_issue_add_note SPIKE-1 "Investigated: cache header"',
  targets: ["SPIKE-1"],
  effects: ["write"],
  workspace: "sample-repository",
  task_id: "task-mcp",
  contract_id: "contract-mcp",
  contract_version: 1,
  authority_epoch: 1,
  environment: "sandbox",
  reasons: ["supervision:confirm_required_operation"],
  expires_at: "2027-09-09T22:00:00Z",
  family: "mcp",
  tool: "sentinel_issue_add_note",
  arguments: { issue_id: "SPIKE-1", body: "Investigated: cache header" },
};

async function installRoutes(page: Page, options: { connected: boolean }) {
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
        mandatory_agent_connected: options.connected,
        connection_message: options.connected
          ? "Cursor MCP shim connected. Only the fixture tool family is mandatory."
          : "No mandatory agent connected.",
        integration: options.connected ? integration : null,
      },
    }),
  );
  await page.route(`${apiOrigin}/control/authority/active`, (route) =>
    route.fulfill({ json: { active_contract: fixtureAuthority } }),
  );
  await page.route(`${apiOrigin}/control/approvals`, (route) =>
    route.fulfill({ json: { approvals: options.connected ? [mcpApproval] : [] } }),
  );
  await page.route(`${apiOrigin}/control/proposals/pending`, (route) =>
    route.fulfill({ json: { proposal: null, recent: [] } }),
  );
}

test("settings shows honest per-family coverage when the MCP shim is connected", async ({
  page,
}) => {
  await installRoutes(page, { connected: true });
  await page.goto("/settings");

  await expect(page.getByText("Cursor (MCP)", { exact: true })).toBeVisible();
  const coverage = page.getByRole("region", { name: "Agent coverage" });
  await expect(coverage.getByText("Cursor MCP connection")).toBeVisible();
  await expect(coverage.getByText("Connected", { exact: true })).toBeVisible();
  await expect(
    coverage.getByText("Last: sentinel_issue_read · allow · 3 mediated, 1 rejected"),
  ).toBeVisible();
  await expect(coverage.getByText("Not verifiable")).toBeVisible();
  await expect(coverage.getByText("Fixture issue tools (MCP)")).toBeVisible();
  await expect(coverage.getByText("Mandatory", { exact: true })).toBeVisible();
  await expect(coverage.getByText("Advisory", { exact: true })).toBeVisible();
  await expect(coverage.getByText("Unsupported", { exact: true })).toBeVisible();
  await expect(coverage.getByText(/Known limit: same-user agent/)).toBeVisible();
  await expect(page.getByText(/fully protected/i)).toHaveCount(0);
});

test("overview stays focused on the task and attention, not MCP detail", async ({
  page,
}) => {
  await installRoutes(page, { connected: true });
  await page.goto("/");

  await expect(page.getByText("Agent connected", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Agent coverage" })).toHaveCount(0);
  await expect(page.getByText("Fixture issue tools (MCP)")).toHaveCount(0);
});

test("overview explains when no mandatory agent path is running", async ({
  page,
}) => {
  await installRoutes(page, { connected: false });
  await page.goto("/settings");

  await expect(page.getByText("Agent enforcement advisory", { exact: true })).toBeVisible();
  await expect(
    page.getByText(/No mandatory agent path is running in this Sentinel process/),
  ).toBeVisible();
});

test("MCP approval card shows the exact tool and arguments, not a shell command", async ({
  page,
}) => {
  await installRoutes(page, { connected: true });
  await page.goto("/approvals");

  await expect(
    page.getByRole("heading", { name: "Add a note to issue SPIKE-1" }),
  ).toBeVisible();
  await expect(
    page.getByText("One note will be added to the local fixture issue"),
  ).toBeVisible();
  await expect(page.getByText("Tool", { exact: true })).toBeVisible();
  await expect(page.getByText("sentinel_issue_add_note", { exact: true })).toBeVisible();
  await expect(page.getByText("Cursor MCP · mediated by Sentinel")).toBeVisible();
  await expect(page.getByText("Exact arguments")).toBeVisible();
  await expect(page.getByText(/"body": "Investigated: cache header"/)).toBeVisible();
  await expect(page.getByText("Command", { exact: true })).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Approve exact action" }),
  ).toBeEnabled();
});

test("approving an MCP write shows success without a shell execution record", async ({
  page,
}) => {
  await installRoutes(page, { connected: true });
  await page.route(`${apiOrigin}/control/approvals/approval-mcp-1/approve`, (route) =>
    route.fulfill({
      json: {
        approval_id: "approval-mcp-1",
        status: "approved",
        retry: {
          request_id: "req-retry-1",
          verdict: "allow",
          risk_score: 0.1,
          risk_tier: "low",
          reasons: ["mcp:approved_write_applied", "fixture:succeeded"],
          routing_path: "approval",
          agent_message: "The approved note was applied exactly once.",
          approval_id: "approval-mcp-1",
          execution: null,
        },
      },
    }),
  );
  await page.goto("/approvals");

  await page.getByRole("button", { name: "Approve exact action" }).click();

  await expect(page.getByText("Approved and applied")).toBeVisible();
  await expect(page.getByText("Approved; execution failed")).toHaveCount(0);
  await expect(page.getByText("Outcome needs verification")).toHaveCount(0);
});
