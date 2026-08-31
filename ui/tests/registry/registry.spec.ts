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
  test.use({ storageState: "playwright/.auth/manage_registry_user.json" });

  test.beforeEach(async () => {
    test.skip(
      !fixtureMode,
      "Registry browser acceptance is available only through the self-contained fixture profile.",
    );
    await controlledRegistryFixture.reset();
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
      const builtInSnapshotBefore = await controlledRegistryFixture.snapshot();
      await registryPage.verifyBuiltInArtifactIsNonInstallable(
        "Fixture built-in provider",
      );
      const builtInSnapshotAfter = await controlledRegistryFixture.snapshot();
      expect(builtInSnapshotAfter.artifactSubmissionCount).toBe(
        builtInSnapshotBefore.artifactSubmissionCount,
      );
      expect(builtInSnapshotAfter.artifactTaskReadCount).toBe(
        builtInSnapshotBefore.artifactTaskReadCount,
      );
      expect(builtInSnapshotAfter.artifactReadCount).toBe(
        builtInSnapshotBefore.artifactReadCount,
      );
      expect(builtInSnapshotAfter.artifactEvents).toEqual(
        builtInSnapshotBefore.artifactEvents,
      );
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
      await registryPage.addLatest("Fixture shared policy");
      await registryPage.verifyAddedInMyArtifacts("Fixture shared policy");
      await registryPage.removeArtifact("Fixture shared policy");

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
      const addButton = registryPage.addButtonFor("Fixture network audit");
      await addButton.focus();
      await addButton.press("Enter");
      await expect(
        page.getByText("Artifact added", { exact: true }),
      ).toBeVisible();
    },
  );
});
