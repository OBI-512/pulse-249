import { expect, test, type Page } from "@playwright/test";

const viewerUsername = process.env.E2E_VIEWER_USERNAME || "viewer";
const viewerPassword = process.env.E2E_VIEWER_PASSWORD || "Viewer123!";
const adminUsername = process.env.E2E_ADMIN_USERNAME || "admin";
const adminPassword = process.env.E2E_ADMIN_PASSWORD || "Admin123!";
const apiBase = process.env.E2E_API_BASE_URL || "http://127.0.0.1:8000/api";

async function login(page: Page, username: string, password: string) {
  await page.goto("/");
  await page.getByLabel("Username").fill(username);
  await page.getByRole("textbox", { name: "Password", exact: true }).fill(password);
  await page.getByRole("button", { name: /^Sign in$/i }).click();

  const notice = page.getByRole("dialog", { name: "Authorized Use Notice" });
  const currentView = page.getByLabel(/Current view: Overview/i);

  // Login resolves asynchronously: wait for either the mandatory notice or
  // the application shell before deciding whether acknowledgement is needed.
  await expect(notice.or(currentView)).toBeVisible();
  if (await notice.isVisible()) {
    await page.getByRole("button", { name: /I ACKNOWLEDGE AND CONTINUE/i }).click();
  }
  await expect(currentView).toBeVisible();
}

test("login and authorization smoke", async ({ page, request }) => {
  await login(page, viewerUsername, viewerPassword);

  await page.getByRole("button", { name: "Open application navigation" }).click();
  await expect(page.getByRole("button", { name: "Groups Organizational grouping", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /User Management/i })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^Settings/i })).toHaveCount(0);

  const token = await page.evaluate(() =>
    sessionStorage.getItem("fttw_session_token") || localStorage.getItem("fttw_session_token") || "",
  );
  expect(token).not.toBe("");

  const forbidden = await request.get(`${apiBase}/admin/users`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(forbidden.status()).toBe(403);
});

test("custom group create-to-recycle lifecycle smoke", async ({ page }) => {
  await login(page, adminUsername, adminPassword);
  await page.getByRole("button", { name: /^Groups$/ }).first().click();
  await expect(page.getByRole("heading", { name: "Device Groups" })).toBeVisible();

  const suffix = `${Date.now()}`.slice(-8);
  const groupName = `CI Smoke Group ${suffix}`;
  const groupCode = `CI-SMOKE-${suffix}`;

  await page.getByRole("button", { name: "Create Group" }).click();
  await page.getByRole("textbox", { name: "Name *", exact: true }).fill(groupName);
  await page.getByRole("textbox", { name: "Code *", exact: true }).fill(groupCode);
  await page.getByRole("button", { name: /^Create$/ }).click();
  await expect(page.getByText("Group created.")).toBeVisible();

  const search = page.getByPlaceholder("Search groups...");
  await search.fill(groupCode);
  await expect(page.getByRole("button", { name: groupName })).toBeVisible();
  await page.getByRole("button", { name: groupName }).click();

  await page.getByRole("button", { name: "Move Group to Recycle Bin" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Move selected groups to Recycle Bin");
  await dialog.getByRole("button", { name: "Move selected" }).click();
  await expect(page.getByText(/group\(s\) moved to the Recycle Bin/i)).toBeVisible();

  await search.fill(groupCode);
  await expect(page.getByRole("button", { name: groupName })).toHaveCount(0);
});
