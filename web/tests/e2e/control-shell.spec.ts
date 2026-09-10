import { expect, test } from "@playwright/test";

const apiOrigin = "http://127.0.0.1:8000";
const testCapability = "test-only-capability-not-a-secret-123456";

test("pairs from the fragment, clears it, and renders server authority", async ({
  page,
}) => {
  let paired = false;
  await page.route(`${apiOrigin}/control/pair/exchange`, async (route) => {
    expect(route.request().postDataJSON()).toEqual({
      capability: testCapability,
    });
    await new Promise((resolve) => setTimeout(resolve, 75));
    paired = true;
    await route.fulfill({
      json: {
        paired: true,
        absolute_expires_at: "2026-09-08T22:00:00Z",
      },
    });
  });
  await page.route(`${apiOrigin}/control/status`, (route) => {
    if (!paired) {
      return route.fulfill({ status: 401, json: { detail: "Not paired." } });
    }
    return route.fulfill({
      json: {
        paired: true,
        supervision_session_id: "session-1",
        session_absolute_expires_at: "2026-09-08T22:00:00Z",
        workspace: {
          name: "sample-repository",
          canonical_path: "/tmp/sample-repository",
          identity_sha256: "a".repeat(64),
        },
        runtime: {
          backend: {
            status: "ready",
            detail: "Protected FastAPI control routes are responding.",
          },
          workspace: {
            status: "ready",
            detail: "Workspace identity was reviewed and fixed at startup.",
          },
          docker: {
            status: "ready",
            detail: "Docker executor is configured and the daemon is available.",
          },
          rules: {
            status: "ready",
            detail:
              "Rules-only enforcement and required audit storage are ready.",
          },
          demo_mode: true,
          sample_repository: "/tmp/sample-repository",
        },
        ml_status: "disabled",
        mandatory_agent_connected: false,
        connection_message: "No mandatory agent connected.",
      },
    });
  });
  await page.route(`${apiOrigin}/control/authority/active`, (route) =>
    route.fulfill({
      json: {
        active_contract: {
          contract_id: "contract-1",
          task_id: "task-1",
          version: 1,
          authority_epoch: 1,
          status: "active",
          expires_at: "2026-09-08T22:00:00Z",
          contract: {
            objective: "Write exactly /workspace/build/result.txt.",
            allowed_operations: ["write"],
            exact_targets: ["/workspace/build/result.txt"],
            environment: "sandbox",
          },
        },
      },
    }),
  );
  await page.route(`${apiOrigin}/control/approvals`, (route) =>
    route.fulfill({ json: { approvals: [] } }),
  );

  await page.goto(`/#pair=${testCapability}`);

  // The pairing fragment must be stripped from the URL regardless of which
  // port the Playwright config serves the UI on.
  await expect(page).toHaveURL(/^http:\/\/127\.0\.0\.1:\d+\/$/);
  await expect(
    page.getByText(
      "Agent enforcement is advisory · No mandatory agent connected.",
    ),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", {
      name: "Write exactly /workspace/build/result.txt.",
    }),
  ).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary" })).toContainText(
    "OverviewTasksApprovalsActivitySettings",
  );
  await page.getByRole("button", { name: "Collapse navigation" }).click();
  await expect(page.getByRole("button", { name: "Expand navigation" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Tasks" }).first()).toBeVisible();
  await page.getByRole("button", { name: "Expand navigation" }).press("Enter");
});

test("fails closed when the local backend is unreachable", async ({ page }) => {
  await page.route(`${apiOrigin}/**`, (route) => route.abort());

  await page.goto("/");

  await expect(
    page.getByRole("heading", {
      name: "Local FastAPI backend is unreachable",
    }),
  ).toBeVisible();
  await expect(page.getByText(/will not use an unprotected connection/i)).toBeVisible();
});
