import { expect, test } from "@playwright/test";

import {
  controlledRegistryFixture,
  FIXTURE_REGISTRY_KEY,
} from "./controlled-registry-fixture";
import { RegistryPage } from "./registry-page";

const fixtureMode = process.env.E2E_REGISTRY_ACCEPTANCE_MODE === "fixture";
const enabledProject = "registry";
const flagOffProject = "registry-flag-off";
const localProject = "registry-local";
const mobileProject = "registry-mobile";

function skipUnlessProject(projectName: string) {
  test.skip(
    test.info().project.name !== projectName,
    `This scenario runs in the ${projectName} fixture profile.`,
  );
}

test.describe.serial("Registry", () => {
  test.setTimeout(60_000);
  test.use({ storageState: "playwright/.auth/manage_registry_user.json" });

  test.beforeEach(async ({ page }) => {
    test.skip(
      !fixtureMode,
      "Registry browser acceptance is available only through the self-contained fixture profile.",
    );
    await controlledRegistryFixture.reset();
    // Exercise the real media CSP without contacting the Registry service.
    await page.route(
      "https://media.registry.dev.prowler.com/fixture-owner.svg",
      (route) =>
        route.fulfill({
          contentType: "image/svg+xml",
          body: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"><circle cx="10" cy="10" r="10" fill="#2563eb"/></svg>',
        }),
    );
  });

  test(
    "fails closed in Local and Registry-flag-off process profiles",
    { tag: ["@critical", "@e2e", "@registry", "@REGISTRY-E2E-001"] },
    async ({ page }) => {
      test.skip(
        ![flagOffProject, localProject].includes(test.info().project.name),
        "This assertion requires the Local or Registry-flag-off fixture profile.",
      );
      const registryPage = new RegistryPage(page);

      await page.goto("/");
      await registryPage.verifyRegistryNavigationHidden();
      await registryPage.goto();
      await registryPage.verifyDirectRouteDenied();
    },
  );

  test(
    "shows the New Registry navigation entry only in the enabled manager profile",
    { tag: ["@critical", "@e2e", "@registry", "@REGISTRY-E2E-002"] },
    async ({ page }) => {
      skipUnlessProject(enabledProject);
      const registryPage = new RegistryPage(page);

      await page.goto("/");
      await registryPage.verifyRegistryNavigationVisible();
      await expect(
        registryPage.registryLink.getByText("New", { exact: true }),
      ).toBeVisible();
    },
  );

  test(
    "denies stale manager storage after controlled current-authority revocation",
    { tag: ["@critical", "@e2e", "@registry", "@REGISTRY-E2E-003"] },
    async ({ page }) => {
      skipUnlessProject(enabledProject);
      const registryPage = new RegistryPage(page);

      await page.goto("/");
      await registryPage.verifyRegistryNavigationVisible();
      await controlledRegistryFixture.revokeCurrentAuthority();
      // No client-side lease machinery: revocation is enforced by the API and
      // lands on the next server-rendered request.
      await page.goto("/");
      await registryPage.verifyRegistryNavigationHidden();
      await registryPage.goto();
      await registryPage.verifyDirectRouteDenied();
    },
  );

  test(
    "keeps an onboarding key write-only while 202 validation settles through an authoritative read",
    { tag: ["@critical", "@e2e", "@registry", "@REGISTRY-E2E-004"] },
    async ({ page }) => {
      skipUnlessProject(enabledProject);
      const registryPage = new RegistryPage(page);
      const requestUrls: string[] = [];
      page.on("request", (request) => requestUrls.push(request.url()));

      await registryPage.goto();
      await registryPage.verifyOnboarding();
      await registryPage.submitRegistryKey(FIXTURE_REGISTRY_KEY);
      // The form stays visible while the task watcher tracks validation: the
      // submit control flips to a disabled Connecting… state.
      await expect(
        page.getByRole("button", { name: "Connecting…" }),
      ).toBeDisabled();
      await expect(page.getByLabel("Registry key")).toBeDisabled();
      await registryPage.verifyKeyIsNotDisclosed(
        FIXTURE_REGISTRY_KEY,
        requestUrls,
      );
      await registryPage.verifyMarketplaceReady();
      await expect(
        page.getByText("Registry connected", { exact: true }),
      ).toBeVisible();

      const snapshot = await controlledRegistryFixture.snapshot();
      expect(snapshot.credentialAccepted).toBe(true);
      expect(snapshot.credentialReadCount).toBeGreaterThanOrEqual(2);
      expect(snapshot.taskReadCount).toBeGreaterThanOrEqual(2);
    },
  );

  test(
    "uses complete catalog data for recovery, direct card Add, and confirmed Remove",
    { tag: ["@critical", "@e2e", "@registry", "@REGISTRY-E2E-005"] },
    async ({ page }) => {
      skipUnlessProject(enabledProject);
      await page.setViewportSize({ height: 900, width: 1440 });
      const registryPage = new RegistryPage(page);

      await registryPage.goto();
      await registryPage.connectFixtureRegistry();
      await registryPage.dismissWelcomeDialog();
      await registryPage.verifyCompleteCatalogSearchAndFilters();
      await registryPage.verifyOwnerRows();
      await registryPage.captureEvidence("registry-catalog-desktop-dark");
      await page.getByRole("switch", { name: "Switch to light mode" }).click();
      await registryPage.captureEvidence("registry-catalog-desktop-light");
      await page.setViewportSize({ width: 800, height: 1000 });
      await registryPage.captureEvidence("registry-catalog-tablet-light");
      await page.setViewportSize({ width: 1440, height: 900 });
      await registryPage.verifyBuiltInArtifactHasNoAdd(
        "Fixture built-in provider",
      );
      await expect(
        registryPage.addButtonFor("Fixture shared policy"),
      ).toBeHidden();
      const artifactSnapshotBefore = await controlledRegistryFixture.snapshot();
      await registryPage.addLatest("Fixture network audit");
      const artifactSnapshotAfter = await controlledRegistryFixture.snapshot();
      expect(artifactSnapshotAfter.artifactSubmissionCount).toBe(
        artifactSnapshotBefore.artifactSubmissionCount + 1,
      );
      expect(artifactSnapshotAfter.artifactTaskReadCount).toBe(2);
      expect(artifactSnapshotAfter.artifactReadCount).toBeGreaterThan(
        artifactSnapshotBefore.artifactReadCount,
      );
      expect(
        artifactSnapshotAfter.artifactEvents.slice(
          artifactSnapshotBefore.artifactEvents.length,
        ),
      ).toEqual(["submission", "task-poll", "task-poll", "authoritative-read"]);
      await registryPage.verifyAddedInMyArtifacts("Fixture network audit");
      await registryPage.removeArtifact("Fixture network audit");
      await page.reload();
      await registryPage.verifyMarketplaceReady();
      await controlledRegistryFixture.setDiscoveryMode("reconnect");
      await page.reload();
      await expect(
        page.getByRole("heading", { name: "Reconnect Registry" }),
      ).toBeVisible();
      await controlledRegistryFixture.setDiscoveryMode("unavailable");
      await page.reload();
      await expect(
        page.getByRole("heading", { name: "Registry is unavailable" }),
      ).toBeVisible();
      await controlledRegistryFixture.setDiscoveryMode("error");
      await page.reload();
      await expect(
        page.getByRole("heading", { name: "Registry could not be loaded" }),
      ).toBeVisible();
    },
  );

  test(
    "keeps keyboard and reduced-motion Registry browsing usable on Pixel 5",
    { tag: ["@high", "@e2e", "@registry", "@REGISTRY-E2E-006"] },
    async ({ page }) => {
      skipUnlessProject(mobileProject);
      const registryPage = new RegistryPage(page);
      await page.emulateMedia({ reducedMotion: "reduce" });
      expect(
        await page.evaluate(
          () => window.matchMedia("(prefers-reduced-motion: reduce)").matches,
        ),
      ).toBe(true);

      await registryPage.goto();
      await registryPage.connectFixtureRegistry();
      await registryPage.dismissWelcomeDialog();
      // With no detail panel, direct card actions are the keyboard path.
      await registryPage.captureEvidence("registry-catalog-mobile-dark");
      const addButton = registryPage.addButtonFor("Fixture network audit");
      await addButton.focus();
      await addButton.press("Enter");
      await expect(
        page.getByText("Artifact added", { exact: true }),
      ).toBeVisible();
    },
  );
  test(
    "installs an external provider and completes the existing account, credentials, connection and scan wizard",
    { tag: ["@critical", "@e2e", "@registry", "@REGISTRY-E2E-007"] },
    async ({ page }) => {
      skipUnlessProject(enabledProject);
      const registry = new RegistryPage(page);
      await registry.goto();
      await registry.connectFixtureRegistry();
      await registry.addLatest("Fixture network audit");
      await registry.connectInstalledProviderAndScan();
      const snapshot = await controlledRegistryFixture.snapshot();
      expect(snapshot).toMatchObject({
        providerCreated: true,
        secretSaved: true,
        connected: true,
        scanCreated: true,
      });
      const browserStorage = await page.evaluate(() =>
        JSON.stringify({
          local: { ...localStorage },
          session: { ...sessionStorage },
        }),
      );
      expect(browserStorage).not.toContain(
        "fixture-provider-token-not-a-secret",
      );
      await registry.goto();
      await registry.removeArtifact("Fixture network audit");
      await page.goto("/providers");
      await expect(
        page.getByRole("row").filter({ hasText: "Registry test account" }),
      ).toBeVisible();
      const beforeOpen = await controlledRegistryFixture.snapshot();
      await page.getByRole("button", { name: /Add (a )?Provider/i }).click();
      await expect
        .poll(
          async () =>
            (await controlledRegistryFixture.snapshot()).artifactReadCount,
        )
        .toBeGreaterThan(beforeOpen.artifactReadCount);
      await expect(
        page.getByRole("option", { name: "Fixture Cloud Registry" }),
      ).toBeHidden();
    },
  );
  test(
    "resumes an installation after reload with one confirmation notification",
    { tag: ["@critical", "@e2e", "@registry", "@REGISTRY-E2E-008"] },
    async ({ page }) => {
      skipUnlessProject(enabledProject);
      const registry = new RegistryPage(page);
      await registry.goto();
      await registry.connectFixtureRegistry();
      await controlledRegistryFixture.holdArtifactTask(true);
      await registry.addButtonFor("Fixture network audit").click();
      await expect
        .poll(() => page.evaluate(() => localStorage.getItem("task-watcher")))
        .toContain('"kind":"registry-artifact-add"');
      await page.reload();
      await registry.verifyMarketplaceReady();
      await expect(
        page.getByText("Artifact added", { exact: true }),
      ).toBeHidden();
      await controlledRegistryFixture.holdArtifactTask(false);
      await expect(
        page.getByText("Artifact added", { exact: true }),
      ).toHaveCount(1);
      await registry.verifyAddedInMyArtifacts("Fixture network audit");
      expect(
        (await controlledRegistryFixture.snapshot()).artifactSubmissionCount,
      ).toBe(1);
    },
  );
});
