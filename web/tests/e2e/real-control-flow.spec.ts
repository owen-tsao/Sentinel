import { expect, test, type Page } from "@playwright/test";
import { stat } from "node:fs/promises";
import path from "node:path";

test.use({ viewport: { width: 1440, height: 1000 } });

const apiOrigin = "http://127.0.0.1:8000";
const pairingCapability = "playwright-real-control-" + "a".repeat(40);
const markerTarget = "/workspace/build/result.txt";
const markerPath = path.resolve(
  process.cwd(),
  "test-results/real-control/sample-repository/build/result.txt",
);
const rawPrompt = "Write /workspace/build/result.txt in production.";
const screenshotDirectory = path.resolve(
  process.cwd(),
  "../docs/screenshots/week11",
);

test("real browser control flow denies once, approves once, and proves audit order", async ({
  page,
  request,
}) => {
  test.setTimeout(90_000);

  await page.goto(`/#pair=${pairingCapability}`);
  await expect(page).toHaveURL("http://127.0.0.1:3000/");
  await expect(
    page.getByText(
      "Agent enforcement is advisory · No mandatory agent connected.",
    ),
  ).toBeVisible();
  await expect(page.getByText("Approval preference")).toBeVisible();
  await expect(page.getByText("Workspace access")).toBeVisible();
  await expect(page.getByText("Protected execution")).toBeVisible();

  const status = await page.evaluate(async (origin) => {
    const response = await fetch(`${origin}/control/status`, {
      credentials: "include",
    });
    return response.json();
  }, apiOrigin);
  expect(status.runtime.backend.status).toBe("ready");
  expect(status.runtime.workspace.status).toBe("ready");
  expect(status.runtime.docker.status).toBe("ready");
  expect(status.runtime.rules.status).toBe("ready");
  await expectAccessiblePage(page);
  await expectAccessibleTokenContrast(page);
  await captureScreenshot(page, "01-overview-ready.png");

  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Sentinel overview", exact: true }),
  ).toBeFocused();
  await expectVisibleKeyboardFocus(page);
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Overview", exact: true }).first(),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Tasks", exact: true }).first(),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL("http://127.0.0.1:3000/tasks");
  await page.getByLabel("Task goal").fill(rawPrompt);
  await page.getByRole("button", { name: "Build task settings" }).click();
  await expect(
    page.getByText("How should this exact change be rolled back?"),
  ).toBeVisible();

  await page
    .getByLabel("Expected outcome")
    .fill("Create exactly one disposable marker file.");
  await page
    .getByLabel("If something goes wrong")
    .fill("Remove /workspace/build/result.txt.");
  await page.getByLabel("Test first").click();
  await page
    .getByRole("option", {
      name: "No — continue after the other checks",
      exact: true,
    })
    .click();
  await page.getByText("Advanced settings").click();
  for (const checkbox of await page.getByLabel("Reviewed").all()) {
    await checkbox.check();
  }
  await expectAccessiblePage(page);
  await captureScreenshot(page, "02-tasks-reviewed-draft.png");

  const proposedResponsePromise = page.waitForResponse(
    (response) =>
      response.url() === `${apiOrigin}/control/contracts/draft` &&
      response.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Save task settings" }).click();
  const proposedResponse = await proposedResponsePromise;
  const proposedBody = await proposedResponse.json();
  expect(proposedBody.proposed_contract.status).toBe("proposed");
  await expect(
    page.getByText(/cannot act until you activate this task/i),
  ).toBeVisible();

  const activationResponsePromise = page.waitForResponse(
    (response) =>
      response.url() === `${apiOrigin}/control/contracts/activate` &&
      response.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Activate task" })
    .click();
  const activationResponse = await activationResponsePromise;
  const active = (await activationResponse.json()).active_contract;
  await expect(
    page.getByRole("heading", { name: "Contract active" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.getByText("Active task").last()).toBeVisible();
  await expect(page.getByText("Approval mode is on.")).toBeVisible();

  const deniedPayload = actionPayload(active, "playwright-denied");
  const deniedRequest = await request.post(`${apiOrigin}/execute`, {
    data: deniedPayload,
  });
  expect(deniedRequest.ok()).toBeTruthy();
  const deniedRequestBody = await deniedRequest.json();
  expect(deniedRequestBody.verdict).toBe("confirm_required");
  expect(deniedRequestBody.approval_id).toBeTruthy();

  await page.getByRole("link", { name: "Approvals" }).first().click();
  await expect(
    page.getByRole("heading", { name: "Change build/result.txt" }),
  ).toBeVisible();
  await expectAccessiblePage(page);
  await captureScreenshot(page, "03-approvals-pending.png");
  await page.getByRole("button", { name: "Deny" }).click();
  await expect(page.getByText("Change denied")).toBeVisible();
  expect(await markerExists()).toBe(false);
  await captureScreenshot(page, "04-approvals-denied.png");

  const approvedPayload = actionPayload(active, "playwright-approved");
  const approvalRequest = await request.post(`${apiOrigin}/execute`, {
    data: approvedPayload,
  });
  expect(approvalRequest.ok()).toBeTruthy();
  const approvalRequestBody = await approvalRequest.json();
  expect(approvalRequestBody.verdict).toBe("confirm_required");
  expect(approvalRequestBody.approval_id).toBeTruthy();

  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Change build/result.txt" }),
  ).toBeVisible();
  const approveButton = page.getByRole("button", {
    name: "Approve exact action",
  });
  await expect(approveButton).toBeDisabled();
  const typedTarget = page.getByLabel("Type the exact target to approve");
  await typedTarget.focus();
  await page.keyboard.type(markerTarget);
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  await expect(approveButton).toBeFocused();
  await expectVisibleKeyboardFocus(page);

  const approvalResponsePromise = page.waitForResponse(
    (response) =>
      response.url().endsWith(
        `/control/approvals/${approvalRequestBody.approval_id}/approve`,
      ) && response.request().method() === "POST",
  );
  await page.keyboard.press("Enter");
  const approvalResponse = await approvalResponsePromise;
  const approvalBody = await approvalResponse.json();
  expect(approvalBody.retry.verdict).toBe("allow");
  expect(approvalBody.retry.execution.exit_code).toBe(0);
  await expect(page.getByText("Approved and executed")).toBeVisible();
  await captureScreenshot(page, "05-approvals-approved.png");

  const firstMarkerStat = await stat(markerPath, { bigint: true });
  const replay = await request.post(`${apiOrigin}/execute`, {
    data: approvedPayload,
  });
  expect(await replay.json()).toEqual(approvalBody.retry);
  const replayedMarkerStat = await stat(markerPath, { bigint: true });
  expect(replayedMarkerStat.mtimeNs).toBe(firstMarkerStat.mtimeNs);

  await page.getByRole("link", { name: "Activity" }).first().click();
  await expect(
    page.getByRole("button", { name: /View exact_action_denied event/ }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /View execution_admitted event/ }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /View post_execution event/ }),
  ).toBeVisible();

  const filteredAuditPromise = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return (
      url.pathname === "/control/audit" &&
      url.searchParams.get("task_id") === active.task_id
    );
  });
  await page.getByLabel("Task reference").fill(active.task_id);
  await page.getByRole("button", { name: "Apply filters" }).click();
  const auditBody = await (await filteredAuditPromise).json();
  await expect(
    page.getByRole("button", { name: /View exact_action_denied event/ }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /View exact_action_approved event/ }),
  ).toBeVisible();

  const eventTypes = auditBody.events.map(
    (event: { event_type: string }) => event.event_type,
  );
  const sequenceIds = auditBody.events.map(
    (event: { sequence_id: number }) => event.sequence_id,
  );
  expect(sequenceIds).toEqual(
    Array.from({ length: 14 }, (_, index) => index + 1),
  );
  const deniedIndex = eventTypes.indexOf("exact_action_denied");
  const approvedIndex = eventTypes.indexOf("exact_action_approved");
  const admittedIndex = eventTypes.indexOf("execution_admitted");
  const resultIndex = eventTypes.indexOf("post_execution");
  expect(deniedIndex).toBeGreaterThanOrEqual(0);
  expect(approvedIndex).toBeGreaterThan(deniedIndex);
  expect(admittedIndex).toBeGreaterThan(approvedIndex);
  expect(resultIndex).toBeGreaterThan(admittedIndex);
  expect(
    eventTypes.filter((eventType: string) => eventType === "execution_admitted"),
  ).toHaveLength(1);
  const auditText = JSON.stringify(auditBody);
  expect(auditText).not.toContain(rawPrompt);
  expect(auditText).not.toContain(pairingCapability);

  const resultEvent = auditBody.events.find(
    (event: { event_type: string; sequence_id: number }) =>
      event.event_type === "post_execution",
  );
  expect(resultEvent).toBeDefined();
  if (!resultEvent) throw new Error("post_execution audit event is required");
  const resultButton = page.getByRole("button", {
    name: `View post_execution event sequence ${resultEvent.sequence_id}`,
  });
  await page.getByRole("button", { name: "Apply filters" }).focus();
  await page.keyboard.press("Tab");
  await expect(resultButton).toBeFocused();
  await expectVisibleKeyboardFocus(page);
  await page.keyboard.press("Enter");
  await expect(page.getByText("Activity details")).toBeVisible();
  await expect(page.getByText(`#${resultEvent.sequence_id}`)).toBeVisible();
  await expectAccessiblePage(page);
  await captureScreenshot(page, "06-audit-complete.png");
});

function actionPayload(
  active: {
    contract_id: string;
    version: number;
    session_id: string;
  },
  attemptId: string,
) {
  return {
    contract_id: active.contract_id,
    version: active.version,
    attempt_id: attemptId,
    session_id: active.session_id,
    agent_id: "playwright-demo-agent",
    user_id: "playwright-local-user",
    action: {
      family: "shell",
      raw_command: `touch ${markerTarget}`,
      cwd: "/workspace",
    },
    recent_actions: [],
  };
}

async function markerExists() {
  try {
    await stat(markerPath);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function expectAccessiblePage(page: Page) {
  await expect(page.locator("main h1")).toHaveCount(1);
  const violations = await page.locator("body").evaluate((body) => {
    const issues: string[] = [];
    const ids = new Set<string>();
    for (const element of body.querySelectorAll<HTMLElement>("[id]")) {
      if (ids.has(element.id)) issues.push(`duplicate id: ${element.id}`);
      ids.add(element.id);
    }

    const controls = body.querySelectorAll<HTMLElement>(
      "a[href], button, input, select, textarea, summary, [tabindex]",
    );
    for (const control of controls) {
      if (
        control.hidden ||
        control.getAttribute("aria-hidden") === "true" ||
        control.getClientRects().length === 0
      ) {
        continue;
      }
      const labelledBy = control
        .getAttribute("aria-labelledby")
        ?.split(/\s+/)
        .map((id) => document.getElementById(id)?.textContent?.trim() ?? "")
        .join(" ");
      const labels =
        "labels" in control && control.labels
          ? Array.from(control.labels as NodeListOf<HTMLLabelElement>)
              .map((label) => label.textContent?.trim() ?? "")
              .join(" ")
          : "";
      const name =
        control.getAttribute("aria-label")?.trim() ||
        labelledBy?.trim() ||
        labels.trim() ||
        control.textContent?.trim() ||
        control.getAttribute("title")?.trim();
      if (!name) {
        issues.push(`unnamed control: ${control.tagName.toLowerCase()}`);
      }
    }
    return issues;
  });
  expect(violations).toEqual([]);
}

async function expectVisibleKeyboardFocus(page: Page) {
  const focusStyle = await page.evaluate(() => {
    const active = document.activeElement;
    if (!(active instanceof HTMLElement)) return null;
    const style = getComputedStyle(active);
    return {
      outline: style.outlineStyle,
      shadow: style.boxShadow,
    };
  });
  expect(focusStyle).not.toBeNull();
  expect(
    focusStyle?.outline !== "none" ||
      (focusStyle.shadow !== "none" && focusStyle.shadow !== ""),
  ).toBe(true);
}

async function captureScreenshot(page: Page, filename: string) {
  if (process.env.SENTINEL_CAPTURE_WEEK11_SCREENSHOTS !== "1") return;
  await page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        window.scrollTo(0, 0);
        requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
      }),
  );
  await page.screenshot({
    path: path.join(screenshotDirectory, filename),
    fullPage: true,
    animations: "disabled",
    style: "nextjs-portal { display: none !important; }",
  });
}

async function expectAccessibleTokenContrast(page: Page) {
  const ratios = await page.evaluate(() => {
    const root = getComputedStyle(document.documentElement);
    const colors = ["--ink", "--subtext", "--faint", "--success", "--warning", "--danger"];
    const surfaces = ["--paper", "--canvas"];

    function luminance(color: string) {
      const match = color.trim().match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
      if (!match) throw new Error(`Expected a hex color token: ${color}`);
      const hex =
        match[1].length === 3
          ? match[1]
              .split("")
              .map((character) => character.repeat(2))
              .join("")
          : match[1];
      const channels = [0, 2, 4].map(
        (offset) => Number.parseInt(hex.slice(offset, offset + 2), 16) / 255,
      );
      const linear = channels.map((channel) =>
        channel <= 0.04045
          ? channel / 12.92
          : ((channel + 0.055) / 1.055) ** 2.4,
      );
      return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
    }

    return colors.flatMap((foreground) =>
      surfaces.map((background) => {
        const foregroundLuminance = luminance(
          root.getPropertyValue(foreground),
        );
        const backgroundLuminance = luminance(
          root.getPropertyValue(background),
        );
        const lighter = Math.max(foregroundLuminance, backgroundLuminance);
        const darker = Math.min(foregroundLuminance, backgroundLuminance);
        return {
          pair: `${foreground} on ${background}`,
          ratio: (lighter + 0.05) / (darker + 0.05),
        };
      }),
    );
  });
  expect(ratios.filter(({ ratio }) => ratio < 4.5)).toEqual([]);
}
