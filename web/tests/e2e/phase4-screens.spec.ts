import { expect, test, type Page } from "@playwright/test";

const apiOrigin = "http://127.0.0.1:8000";

const activeContract = {
  contract_id: "contract-1",
  task_id: "task-1",
  session_id: "session-1",
  version: 1,
  authority_epoch: 1,
  status: "active",
  authorization_source: "protected_local_ui",
  authorization_reference: "event-1",
  preflight_status: "complete",
  created_at: "2026-09-08T21:00:00Z",
  updated_at: "2026-09-08T21:00:00Z",
  expires_at: "2027-09-08T22:00:00Z",
  contract: {
    objective: "Write exactly /workspace/build/result.txt.",
    allowed_operations: ["write"],
    allowed_tools: ["shell"],
    exact_targets: ["/workspace/build/result.txt"],
    environment: "sandbox",
    maximum_scope: "exact",
    expected_side_effects: [
      "Write exactly /workspace/build/result.txt.",
    ],
    allowed_effects: ["write"],
    forbidden_operations: ["credential_access", "network"],
    forbidden_effects: ["No credential access or network communication."],
    forbidden_effect_codes: ["credential_access", "network"],
    rollback_plan: "Remove the exact created file.",
    dry_run_required: true,
  },
};

async function installBaseRoutes(
  page: Page,
  options: {
    authority?: typeof activeContract | null;
    approvals?: unknown[];
  } = {},
) {
  await page.route(`${apiOrigin}/control/status`, (route) =>
    route.fulfill({
      json: {
        paired: true,
        supervision_session_id: "session-1",
        session_absolute_expires_at: "2027-09-08T22:00:00Z",
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
          demo_mode: true,
          sample_repository: "/tmp/sample-repository",
        },
        ml_status: "disabled",
        mandatory_agent_connected: false,
        connection_message: "No mandatory agent connected.",
      },
    }),
  );
  await page.route(`${apiOrigin}/control/authority/active`, (route) =>
    route.fulfill({
      json: { active_contract: options.authority ?? null },
    }),
  );
  await page.route(`${apiOrigin}/control/approvals`, (route) =>
    route.fulfill({ json: { approvals: options.approvals ?? [] } }),
  );
}

test("overview renders authoritative workspace settings and demo boundary", async ({
  page,
}) => {
  await installBaseRoutes(page, { authority: activeContract });

  await page.goto("/");

  await expect(page.getByText("Approval preference")).toBeVisible();
  await expect(page.getByText("Workspace access")).toBeVisible();
  await expect(page.getByText("Protected execution")).toBeVisible();
  await expect(page.getByText("Decision policy")).toBeVisible();
  await expect(page.getByText("sample-repository").first()).toBeVisible();
  await expect(
    page.getByRole("heading", {
      name: "Write exactly /workspace/build/result.txt.",
    }),
  ).toBeVisible();
  await expect(
    page.getByText(/actions routed through Sentinel are limited/i),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Create replacement task" }),
  ).toBeVisible();
});

test("create task warning draws the blue underline on hover", async ({ page }) => {
  await installBaseRoutes(page);
  await page.goto("/");

  const createTask = page.getByRole("link", { name: "Create task" });
  await createTask.hover();
  await page.waitForTimeout(250);

  const underline = await createTask.evaluate(
    (element) => getComputedStyle(element, "::after").transform,
  );
  expect(underline).not.toBe("matrix(0, 0, 0, 1, 0, 0)");
});

test("settings navigation, connection search, and real brand icons work", async ({
  page,
}) => {
  await installBaseRoutes(page, { authority: activeContract });

  await page.goto("/settings");

  await expect(page.getByRole("img", { name: "GitHub" })).toBeVisible();
  await expect(page.getByRole("img", { name: "Slack" })).toBeVisible();
  await expect(page.getByRole("img", { name: "Linear" })).toBeVisible();

  await page.getByLabel("Search connections").fill("Slack");
  await expect(
    page.getByRole("paragraph").filter({ hasText: /^Slack$/ }),
  ).toBeVisible();
  await expect(
    page.getByRole("paragraph").filter({ hasText: /^GitHub$/ }),
  ).toBeHidden();

  await page.getByRole("button", { name: "Approval preferences" }).click();
  await expect(page.getByText("One-use decisions")).toBeVisible();
});

test("task review keeps proposal and activation as separate actions", async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  let active: typeof activeContract | null = null;
  const suggestions = [
    ["operation", "write", "prompt_inference"],
    ["exact_targets", ["/workspace/build/result.txt"], "prompt_explicit"],
    ["environment", "sandbox", "prompt_explicit"],
    ["allowed_tools", ["shell"], "safe_default"],
    ["maximum_scope", "exact", "safe_default"],
    [
      "forbidden_operations",
      ["credential_access", "network"],
      "safe_default",
    ],
    [
      "forbidden_effects",
      ["No credential access or network communication."],
      "safe_default",
    ],
    [
      "forbidden_effect_codes",
      ["credential_access", "network"],
      "safe_default",
    ],
    ["expires_in_minutes", 60, "safe_default"],
    ["allowed_effects", ["write"], "deterministic_derivation"],
    [
      "expected_side_effects",
      ["Write exactly /workspace/build/result.txt."],
      "deterministic_derivation",
    ],
  ].map(([field, value, source]) => ({
    field,
    value,
    source,
    requires_review: true,
  }));
  const questions = [
    {
      question_id: "rollback_plan",
      field: "rollback_plan",
      prompt: "How should this exact change be rolled back?",
    },
    {
      question_id: "dry_run_required",
      field: "dry_run_required",
      prompt: "Must the agent complete a dry run before the change?",
    },
  ];

  await installBaseRoutes(page);
  await page.unroute(`${apiOrigin}/control/authority/active`);
  await page.route(`${apiOrigin}/control/authority/active`, (route) =>
    route.fulfill({ json: { active_contract: active } }),
  );
  await page.route(`${apiOrigin}/control/contracts/draft`, async (route) => {
    const payload = route.request().postDataJSON();
    await route.fulfill({
      json: {
        prompt_sha256: "b".repeat(64),
        suggestions,
        questions,
        proposed_contract: payload.accepted_contract
          ? { ...activeContract, status: "proposed" }
          : null,
      },
    });
  });
  await page.route(`${apiOrigin}/control/contracts/activate`, async (route) => {
    expect(route.request().postDataJSON()).toEqual({
      contract_id: "contract-1",
      expected_version: 1,
      expected_active_task_id: null,
    });
    active = activeContract;
    await route.fulfill({ json: { active_contract: activeContract } });
  });

  await page.goto("/tasks");
  await page
    .getByLabel("Task goal")
    .fill("Create /workspace/build/result.txt in sandbox.");
  await expect(page.getByText("Behind the contract")).toBeVisible();
  await page.getByRole("button", { name: "Build task settings" }).click();

  await expect(
    page.getByText("How should this exact change be rolled back?"),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Task contract", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Setup progress")).toHaveCount(0);
  await expect(page.getByText("Suggested").first()).toBeVisible();
  await page
    .getByLabel("If something goes wrong")
    .fill("Remove the exact created file.");
  await chooseOption(
    page,
    "Run a dry run first",
    "Yes — the agent must preview shell changes before applying them",
  );
  // Only the five authority-granting fields carry a review checkbox now;
  // advanced settings are accepted unless changed.
  await expect(page.getByLabel("Reviewed")).toHaveCount(5);
  for (const checkbox of await page.getByLabel("Reviewed").all()) {
    await checkbox.check();
  }
  await page.getByRole("button", { name: "Save task settings" }).click();

  await expect(
    page.getByText(/cannot act until you activate this task/i),
  ).toBeVisible();
  await expect(
    page.getByRole("combobox", { name: "Operation", exact: true }),
  ).toBeDisabled();
  await page
    .getByRole("button", { name: "Activate task" })
    .click();
  await expect(
    page.getByRole("heading", { name: "Contract active" }),
  ).toBeVisible();
  await expect(page.getByText("sandbox", { exact: true }).last()).toBeVisible();
  const receipt = page.getByRole("dialog");
  await expect(receipt).toBeVisible();
  await expect(page.getByRole("button", { name: "Done" })).toBeFocused();
  await expect(receipt.locator(".contract-receipt")).toHaveCSS(
    "animation-name",
    "none",
  );
  await page.keyboard.press("Escape");
  await expect(receipt).toBeHidden();
  await expect(page.getByRole("button", { name: "Edit goal" })).toBeFocused();
  await expect(page.getByText("Active task").last()).toBeVisible();
});

test("task entry stacks cleanly on a narrow screen", async ({ page }) => {
  await installBaseRoutes(page);
  await page.setViewportSize({ width: 390, height: 844 });

  await page.goto("/tasks");

  await expect(page.getByLabel("Task goal")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Build task settings" }),
  ).toBeVisible();
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
});

test("task goals enforce the backend UTF-8 byte limit before submission", async ({
  page,
}) => {
  let draftCalls = 0;
  await installBaseRoutes(page);
  await page.route(`${apiOrigin}/control/contracts/draft`, async (route) => {
    draftCalls += 1;
    await route.fulfill({ status: 500, json: { detail: "Should not run." } });
  });

  await page.goto("/tasks");
  await page.getByLabel("Task goal").fill("€".repeat(11_000));
  await page.getByRole("button", { name: "Build task settings" }).click();

  await expect(
    page.getByText("Task goal must be 32,000 bytes or fewer."),
  ).toBeVisible();
  expect(draftCalls).toBe(0);
});

test("destructive approval requires the exact target before retry", async ({
  page,
}) => {
  const pending = {
    approval_id: "approval-1",
    attempt_id: "attempt-1",
    operation: "delete",
    raw_command: "rm /workspace/build/result.txt",
    targets: ["/workspace/build/result.txt"],
    effects: ["delete"],
    workspace: "/workspace",
    task_id: "task-1",
    contract_id: "contract-1",
    contract_version: 1,
    authority_epoch: 1,
    environment: "sandbox",
    reasons: ["Destructive exact action requires human confirmation."],
    expires_at: "2027-09-08T22:00:00Z",
  };
  const deleteAuthority = {
    ...activeContract,
    contract: {
      ...activeContract.contract,
      objective: "Delete exactly /workspace/build/result.txt.",
      allowed_operations: ["delete"],
      allowed_effects: ["delete"],
    },
  };
  await installBaseRoutes(page, {
    authority: deleteAuthority as typeof activeContract,
    approvals: [pending],
  });
  await page.route(
    `${apiOrigin}/control/approvals/approval-1/approve`,
    async (route) => {
      expect(route.request().postDataJSON()).toEqual({
        typed_target: "/workspace/build/result.txt",
      });
      await route.fulfill({
        json: {
          approval_id: "approval-1",
          status: "approved",
          retry: {
            request_id: "request-1",
            verdict: "allow",
            reasons: [],
            execution: {
              stdout: "",
              stderr: "",
              exit_code: 0,
              timed_out: false,
              duration_ms: 12,
              error: null,
            },
          },
        },
      });
    },
  );

  await page.goto("/approvals");
  await expect(
    page.getByText("rm /workspace/build/result.txt", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("/workspace/build/result.txt", { exact: true }).first(),
  ).toBeVisible();
  await expect(
    page.getByText("Destructive exact action requires human confirmation.", {
      exact: true,
    }),
  ).toBeVisible();
  const approve = page.getByRole("button", { name: "Approve exact action" });
  await expect(approve).toBeDisabled();
  await page
    .getByLabel("Type the exact target to approve")
    .fill("/workspace/build/result.txt");
  await expect(approve).toBeEnabled();
  await approve.click();

  await expect(page.getByText("Approved and executed")).toBeVisible();
  await expect(
    page.getByText(/completed the exact action successfully/i),
  ).toBeVisible();
});

test("approved retry that fails admission is not reported as executed", async ({
  page,
}) => {
  const pending = {
    approval_id: "approval-blocked",
    attempt_id: "attempt-blocked",
    operation: "write",
    raw_command: "touch /workspace/build/result.txt",
    targets: ["/workspace/build/result.txt"],
    effects: ["write"],
    workspace: "/workspace",
    task_id: "task-1",
    contract_id: "contract-1",
    contract_version: 1,
    authority_epoch: 1,
    environment: "sandbox",
    reasons: ["Approval preference requires confirmation."],
    expires_at: "2027-09-08T22:00:00Z",
  };
  await installBaseRoutes(page, {
    authority: activeContract,
    approvals: [pending],
  });
  await page.route(
    `${apiOrigin}/control/approvals/approval-blocked/approve`,
    (route) =>
      route.fulfill({
        json: {
          approval_id: "approval-blocked",
          status: "approved",
          retry: {
            request_id: "request-blocked",
            verdict: "block",
            reasons: ["execution:unsupported_executor_capability"],
          },
        },
      }),
  );

  await page.goto("/approvals");
  await page.getByRole("button", { name: "Approve exact action" }).click();

  await expect(page.getByText("Approved; retry blocked")).toBeVisible();
  await expect(page.getByText(/did not admit the retry/i)).toBeVisible();
  await expect(page.getByText("Approved and executed")).toHaveCount(0);
});

test("approved retry with an executor error is reported as failed", async ({
  page,
}) => {
  const pending = {
    approval_id: "approval-executor-error",
    attempt_id: "attempt-executor-error",
    operation: "write",
    raw_command: "touch /workspace/build/result.txt",
    targets: ["/workspace/build/result.txt"],
    effects: ["write"],
    workspace: "/workspace",
    task_id: "task-1",
    contract_id: "contract-1",
    contract_version: 1,
    authority_epoch: 1,
    environment: "sandbox",
    reasons: ["Approval preference requires confirmation."],
    expires_at: "2027-09-08T22:00:00Z",
  };
  await installBaseRoutes(page, {
    authority: activeContract,
    approvals: [pending],
  });
  await page.route(
    `${apiOrigin}/control/approvals/approval-executor-error/approve`,
    (route) =>
      route.fulfill({
        json: {
          approval_id: "approval-executor-error",
          status: "approved",
          retry: {
            request_id: "request-executor-error",
            verdict: "allow",
            reasons: [],
            execution: {
              stdout: "",
              stderr: "",
              exit_code: null,
              timed_out: false,
              duration_ms: 4,
              error: "executor launch failed",
            },
          },
        },
      }),
  );

  await page.goto("/approvals");
  await page.getByRole("button", { name: "Approve exact action" }).click();

  await expect(page.getByText("Approved; execution failed")).toBeVisible();
  await expect(page.getByText(/did not complete it successfully/i)).toBeVisible();
  await expect(page.getByText("Approved and executed")).toHaveCount(0);
});

test("approval transport failures report an unknown outcome", async ({ page }) => {
  const pending = {
    approval_id: "approval-unknown",
    attempt_id: "attempt-unknown",
    operation: "delete",
    raw_command: "rm /workspace/build/result.txt",
    targets: ["/workspace/build/result.txt"],
    effects: ["delete"],
    workspace: "/workspace",
    task_id: "task-1",
    contract_id: "contract-1",
    contract_version: 1,
    authority_epoch: 1,
    environment: "sandbox",
    reasons: ["Destructive exact action requires human confirmation."],
    expires_at: "2027-09-08T22:00:00Z",
  };
  const deleteAuthority = {
    ...activeContract,
    contract: {
      ...activeContract.contract,
      objective: "Delete exactly /workspace/build/result.txt.",
      allowed_operations: ["delete"],
      allowed_effects: ["delete"],
    },
  };
  await installBaseRoutes(page, {
    authority: deleteAuthority as typeof activeContract,
    approvals: [pending],
  });
  await page.route(
    `${apiOrigin}/control/approvals/approval-unknown/approve`,
    (route) => route.abort(),
  );

  await page.goto("/approvals");
  await page
    .getByLabel("Type the exact target to approve")
    .fill("/workspace/build/result.txt");
  await page.getByRole("button", { name: "Approve exact action" }).click();

  await expect(page.getByText(/outcome is unknown/i)).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Outcome needs verification" }),
  ).toBeVisible();
  await expect(page.getByText(/nothing was executed/i)).toHaveCount(0);
});

test("audit renders exact evidence, filters, and ordered detail", async ({
  page,
}) => {
  await installBaseRoutes(page);
  await page.route(`${apiOrigin}/control/audit*`, async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get("verdict")) {
      expect(url.searchParams.get("verdict")).toBe("block");
    }
    await route.fulfill({
      json: {
        events: url.searchParams.get("event_type")
          ? []
          : [
              {
                event_id: "event-1",
                sequence_id: 3,
                event_type: "decision",
                timestamp: "2026-09-08T21:04:05Z",
                task_id: "task-1",
                contract_id: "contract-1",
                contract_version: 1,
                environment: "sandbox",
                verdict: "block",
                reason_codes: ["contract:target_mismatch"],
                details: { execution_route: "none" },
              },
            ],
      },
    });
  });

  await page.goto("/audit");
  await expect(
    page.getByRole("button", { name: "View decision event sequence 3" }),
  ).toBeVisible();
  await expect(page.locator("#day-2026-09-08")).toBeVisible();
  await chooseOption(page, "Decision", "Blocked");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await page
    .getByRole("button", { name: "View decision event sequence 3" })
    .click();

  await expect(page.getByText("Activity details")).toBeVisible();
  await expect(
    page.getByText("The requested location was outside the active task."),
  ).toBeVisible();
  await expect(page.getByText("#3")).toBeVisible();

  await chooseOption(page, "Show", "Change completed");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByText("No matching activity")).toBeVisible();
  await expect(page.getByText("Choose an item to see why it happened.")).toBeVisible();
  await expect(page.getByText("#3")).toHaveCount(0);
});

async function chooseOption(page: Page, label: string, option: string) {
  await page.getByLabel(label, { exact: true }).click();
  await page.getByRole("option", { name: option, exact: true }).click();
}
