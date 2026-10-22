import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const EVIDENCE = process.env.E2E_EVIDENCE_DIR ?? "../evidence/e2e";
const SCREENS = join(EVIDENCE, "screens");
mkdirSync(SCREENS, { recursive: true });

// Let finite animations and transitions finish so evidence and audits see settled states, not mid-frame ones.
async function settle(page: Page) {
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running" || a.effect?.getTiming().iterations === Infinity), null, { timeout: 3000 }).catch(() => {});
}

async function shot(page: Page, name: string, fullPage = true) {
  await settle(page);
  await page.screenshot({ path: join(SCREENS, `${test.info().project.name}-${name}.jpg`), type: "jpeg", quality: 70, fullPage });
}

function watch(page: Page) {
  const problems: string[] = [];
  page.on("console", (m) => m.type() === "error" && problems.push(`console: ${m.text()}`));
  page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
  page.on("response", (r) => {
    const url = new URL(r.url());
    if (r.status() >= 400 && url.origin === new URL(page.url() || r.url()).origin) problems.push(`HTTP ${r.status()} ${url.pathname}`);
  });
  return problems;
}

async function noOverflow(page: Page) {
  const [scroll, inner] = await page.evaluate(() => [document.documentElement.scrollWidth, window.innerWidth]);
  expect(scroll, "page must not scroll horizontally").toBeLessThanOrEqual(inner + 1);
}

async function axe(page: Page) {
  await settle(page);
  // @axe-core/playwright is typed against its own Playwright Page version; the runtime object is the same.
  const results = await new AxeBuilder({ page: page as never }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  // Name every failing element and axe's reason so a CI-only failure can be diagnosed from the log alone.
  expect(serious.map((v) => `${v.id}: ${v.nodes.map((n) => `${n.target.join(" ")} (${(n.failureSummary ?? "").replace(/\s+/g, " ").slice(0, 160)})`).join("; ")}`)).toEqual([]);
}

const narrow = (page: Page) => (page.viewportSize()?.width ?? 0) <= 1180;
const BANNED = /\bcompliant\b|compliance achieved|all clear/i;

async function openTab(page: Page, label: RegExp, id: string) {
  await page.getByRole("navigation", { name: "Review sections" }).getByRole("link", { name: label }).click();
  await expect(page).toHaveURL(new RegExp(`tab/${id}$`));
}

test("coverage: statement, tally and legend; partial coverage stated; accessible, no overflow", async ({ page }) => {
  const problems = watch(page);
  await page.goto("./");
  const statement = page.locator("#pf-statement");
  await expect(statement).toBeVisible();
  await expect(page.getByText("Partial coverage")).toBeVisible();
  await expect(page.locator(".pf-tally .pf-mark[data-s='unknown']").first()).toBeVisible();
  await expect(page.locator(".pf-tally .pf-mark[data-s='uncovered']").first()).toBeVisible();
  await expect(page.getByRole("list", { name: "Legend" })).toBeVisible();
  expect(await page.locator("main").innerText()).not.toMatch(BANNED);
  await noOverflow(page);
  await axe(page);
  await shot(page, "overview");
  await shot(page, "overview-first-viewport", false);
  expect(problems).toEqual([]);
});

test("findings: a finding opens its evidence at the cited line", async ({ page }) => {
  const problems = watch(page);
  await page.goto("./");
  const first = page.locator(".pf-finding").first();
  await first.click();
  const panel = page.getByRole("complementary", { name: "Evidence" });
  await expect(panel.locator(".pf-line[data-cited='true']").first()).toBeVisible();
  await expect(panel.getByRole("heading", { level: 2 })).toBeVisible();
  await expect(first).toHaveAttribute("aria-pressed", "true");
  await noOverflow(page);
  await axe(page);
  await shot(page, "evidence", false);
  if (narrow(page)) {
    await page.keyboard.press("Escape");
    await expect(panel).toBeHidden();
  } else {
    await expect(panel.getByRole("button", { name: "Close" })).toBeHidden();
  }
  expect(problems).toEqual([]);
});

test("findings: not-evaluated and excepted views, pack filter", async ({ page }) => {
  await page.goto("./");
  const show = page.getByRole("group", { name: "Show" });
  await show.getByRole("button", { name: /Not evaluated/ }).click();
  await expect(page.locator(".pf-finding .pf-mark[data-s='unknown']").first()).toBeVisible();
  const excepted = show.getByRole("button", { name: /Excepted/ });
  await excepted.click();
  // A run can legitimately have no excepted finding (for example after an exception expires); then the empty state shows.
  if (/Excepted 0$/.test((await excepted.textContent())?.trim() ?? "")) {
    await expect(page.getByText("No finding in this filter is covered by an exception.")).toBeVisible();
  } else {
    await expect(page.locator(".pf-finding .pf-mark[data-s='excepted']").first()).toBeVisible();
  }
  await show.getByRole("button", { name: /Failed/ }).click();
  const packs = page.getByRole("group", { name: "Rule pack" });
  await packs.getByRole("button", { name: "Network" }).click();
  await expect(packs.getByRole("button", { name: "Network" })).toHaveAttribute("aria-pressed", "true");
  await noOverflow(page);
  await shot(page, "findings-filtered", false);
});

test("tabs: every section by link, focus moves to its heading, back button restores", async ({ page }) => {
  const problems = watch(page);
  await page.goto("./");
  await openTab(page, /Policies/, "policies");
  await expect(page.locator("[data-tab-heading]")).toBeFocused();
  await openTab(page, /Rule tests/, "tests");
  await page.goBack();
  await expect(page).toHaveURL(/tab\/policies$/);
  await expect(page.getByRole("heading", { level: 2, name: "Policy catalog" })).toBeVisible();
  for (const [label, id] of [[/Exceptions/, "exceptions"], [/Remediation/, "remediation"], [/Inventory/, "inventory"]] as const) await openTab(page, label, id);
  await noOverflow(page);
  expect(problems).toEqual([]);
});

test("inventory: unsupported types are listed as having no rule", async ({ page }) => {
  await page.goto("./#/tab/inventory");
  await page.getByRole("group", { name: "Resource type" }).getByRole("button", { name: /Unsupported/ }).click();
  const phone = (page.viewportSize()?.width ?? 0) <= 720; // cards below 720 px, the table above
  const open = phone ? page.getByRole("button", { name: "Open resource" }).first() : page.locator(".pf-table tbody th button").first();
  await open.click();
  const panel = page.getByRole("complementary", { name: "Evidence" });
  await expect(panel).toContainText("No rule evaluates");
  await noOverflow(page);
  await axe(page);
  await shot(page, "inventory", false);
});

test("policies: each rule states what it does not evaluate", async ({ page }) => {
  await page.goto("./#/tab/policies");
  const disclosure = page.getByRole("button", { name: "Not evaluated, remediation and scope" }).first();
  await disclosure.click();
  await expect(disclosure).toHaveAttribute("aria-expanded", "true");
  await noOverflow(page);
  await axe(page);
  await shot(page, "policies");
});

test("rule tests: positive, negative and boundary fixtures for every rule, all passing", async ({ page }) => {
  await page.goto("./#/tab/tests");
  const table = page.getByRole("table", { name: "Fixture tests per rule" });
  await expect(table).toBeVisible();
  await expect(table.getByRole("img", { name: /Missing|Failing/ })).toHaveCount(0);
  await noOverflow(page);
  await axe(page);
  await shot(page, "rule-tests");
});

test("exceptions: active, expired and rejected entries with validity spans", async ({ page }) => {
  await page.goto("./#/tab/exceptions");
  const list = page.getByRole("list", { name: "Exceptions" });
  for (const state of ["Active", "Expired", "Rejected"]) await expect(list.getByText(state, { exact: true }).first()).toBeVisible();
  await expect(page.locator(".pf-validity").first()).toBeVisible();
  await noOverflow(page);
  await axe(page);
  await shot(page, "exceptions");
});

test("remediation: verified patch diff, before and after views, download", async ({ page }) => {
  await page.goto("./#/tab/remediation");
  await expect(page.getByRole("link", { name: /Download remediation\.patch/ })).toHaveAttribute("href", /remediation\.patch$/);
  const view = page.getByRole("group", { name: /Patch view for/ }).first();
  await expect(page.locator(".pf-dl[data-k='add']").first()).toBeVisible();
  await view.getByRole("button", { name: "After" }).click();
  await expect(view.getByRole("button", { name: "After" })).toHaveAttribute("aria-pressed", "true");
  await view.getByRole("button", { name: "Before" }).click();
  await expect(page.getByRole("list", { name: "Regression evidence" }).first()).toBeVisible();
  await noOverflow(page);
  await axe(page);
  await shot(page, "remediation");
});

test("keyboard: skip link and visible focus", async ({ page }) => {
  await page.goto("./");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#pf-main")).toBeFocused();
  await page.keyboard.press("Tab");
  const outline = await page.evaluate(() => getComputedStyle(document.activeElement as Element).outlineStyle);
  expect(outline).not.toBe("none");
  await shot(page, "keyboard-focus", false);
});

test("dark theme: the theme control applies and stays accessible", async ({ page }) => {
  await page.goto("./#/tab/remediation");
  await page.getByRole("group", { name: "Colour theme" }).getByRole("button", { name: "Dark" }).click();
  await page.waitForTimeout(500); // theme transitions settle before the audit
  await expect(page.locator(".pf-root")).toHaveAttribute("data-theme", "dark");
  await axe(page);
  // axe reports identical text and background colours as incomplete, not as a violation; check the primary action directly.
  const [fg, bg] = await page.locator(".pf-btn-primary").first().evaluate((el) => [getComputedStyle(el).color, getComputedStyle(el).backgroundColor]);
  expect(fg).not.toBe(bg);
  await shot(page, "dark", false);
});

test("reduced motion: no running animations, tally complete", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("./");
  await expect(page.locator(".pf-tally .pf-mark").first()).toBeVisible();
  const running = await page.evaluate(() => document.getAnimations().filter((a) => a.playState === "running").length);
  expect(running).toBe(0);
  await shot(page, "reduced-motion", false);
});

test("states: loading, empty, error with retry, stale", async ({ page }) => {
  let release: () => void = () => {};
  const gate = new Promise<void>((r) => (release = r));
  await page.route("**/data/snapshot.json", async (route) => { await gate; await route.continue(); });
  await page.goto("./");
  await expect(page.getByRole("status").filter({ hasText: "Loading" })).toBeVisible();
  await shot(page, "state-loading", false);
  release();
  await expect(page.locator("#pf-statement")).toBeVisible();
  await page.unroute("**/data/snapshot.json");

  await page.route("**/data/snapshot.json", async (route) => {
    const res = await route.fetch();
    await route.fulfill({ response: res, json: { ...(await res.json()), latest_run_id: null, runs_included: [] } });
  });
  await page.goto("./?empty");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("No published reviews yet.");
  await shot(page, "state-empty", false);
  await page.unroute("**/data/snapshot.json");

  let fail = true;
  await page.route("**/data/snapshot.json", async (route) => {
    if (fail) await route.fulfill({ status: 503, body: "unavailable" });
    else await route.continue();
  });
  await page.goto("./?error");
  await expect(page.getByRole("alert")).toContainText("The server answered 503");
  await shot(page, "state-error", false);
  fail = false;
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.locator("#pf-statement")).toBeVisible();
  await page.unroute("**/data/snapshot.json");

  await page.route("**/data/snapshot.json", async (route) => {
    const res = await route.fetch();
    await route.fulfill({ response: res, json: { ...(await res.json()), generated_at: "2025-01-01T00:00:00Z" } });
  });
  await page.goto("./?stale");
  await expect(page.getByText(/older than its 14-day freshness window/)).toBeVisible();
  await shot(page, "state-stale", false);
});

test("pages: runs ledger, request form link, about", async ({ page }) => {
  const preview = await page.request.get("./preview.jpg");
  expect(preview.status(), "portfolio preview image (portfolio-manifest.json preview_image)").toBe(200);
  const problems = watch(page);
  await page.goto("./#/runs");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Every review");
  await noOverflow(page);
  await page.goto("./#/request");
  await expect(page.getByRole("link", { name: /Open the review request form/ })).toHaveAttribute("href", /\/issues\/new\?template=run-request\.yml$/);
  await axe(page);
  await page.goto("./#/about");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("what it does not do");
  expect(await page.locator("main").innerText()).not.toMatch(/compliance achieved|all clear/i);
  await noOverflow(page);
  expect(problems).toEqual([]);
});
