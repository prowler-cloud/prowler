import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import {
  buildGcpDiscoveryResult,
  DISCOVERY_STATUS_VALUE,
  GCP_BLOCKED_FOLDER,
  GCP_BLOCKED_FOLDER_NAME,
  GCP_BLOCKED_FOLDER_PROJECT,
  GCP_CREATED_PROVIDER_IDS,
  GCP_EMPTY_FOLDER,
  GCP_EMPTY_FOLDER_NAME,
  GCP_LONG_PROJECT_ID,
  GCP_ORG_ID,
  gcpOnboardingFixture,
  mixedHierarchyFixture,
  type OrgFixture,
} from "@/__tests__/msw/handlers/organizations.fixtures";
import { ORGANIZATION_TYPE } from "@/types/organizations";

import { ProvidersPageHarness } from "./providers-page.harness";

// The GCP Organization flow end to end: method fork, setup, selection tree, apply,
// and the shared safety UX. Discovery timeout/keep-waiting/resume live in the
// submission unit tests instead, since they need fake timers.

const VALID_SA_KEY = JSON.stringify({
  type: "service_account",
  project_id: "prowler-scan",
  private_key_id: "abcdef",
  client_email: "prowler@prowler-scan.iam.gserviceaccount.com",
});

/** The GCP docs tutorial the wizard links to during the org flow. */
const GCP_ORG_DOCS = "prowler-cloud-gcp-organizations";

/** The GCP organization seeded by `mixedHierarchyFixture`. */
const GCP_ORG_NAME = "My GCP Organization";
/** The GCP folder seeded by `mixedHierarchyFixture`, and its node id. */
const GCP_FOLDER_NAME = "Engineering";
const GCP_FOLDER_NODE_ID = "node-gcp-eng";

/** Drive a fresh GCP org onboarding up to the authentication submit. */
async function authenticateGcpOrg(
  harness: ProvidersPageHarness,
  { orgId = GCP_ORG_ID, name }: { orgId?: string; name?: string } = {},
): Promise<void> {
  await harness.mount();
  await harness.chooseGcpOrganizations();
  await harness.fillGcpOrgDetails(orgId, name);
  await harness.submitOrganizationDetails();
  await harness.fillGcpServiceAccountKey(VALID_SA_KEY);
  await harness.authenticate();
}

/** Drive a fresh GCP org onboarding up to the populated selection tree. */
async function onboardGcpToSelection(
  harness: ProvidersPageHarness,
): Promise<void> {
  await authenticateGcpOrg(harness, { name: "My GCP Org" });
  await harness.waitForSelectionTree();
  await harness.waitForProjectSelection();
}

interface ApplyRequestBody {
  data: {
    attributes: {
      projects?: Array<{ project_id: string; alias?: string }>;
      accounts?: unknown;
      organizational_units?: unknown;
    };
  };
}

describe("GCP Organizations onboarding (Phase 2)", () => {
  it("completes the happy path: setup → discovery → selection → apply → connect → launch step", async () => {
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await onboardGcpToSelection(harness);

    // Terminology: the selection step counts "projects", never "accounts".
    expect(harness.hasSelectedProjectCount(2, 2)).toBe(true);
    expect(harness.usesAccountWording()).toBe(false);

    await harness.testConnections();
    await harness.waitForProjectsConnected();

    expect(harness.usesAccountWording()).toBe(false);
    expect(harness.applyCallCount).toBe(1);
  }, 40000);

  it("resolves the created providers' uids with one filtered list, and no include", async () => {
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await onboardGcpToSelection(harness);

    await harness.testConnections();
    await harness.waitForProjectsConnected();

    // The apply view rejects `include`, so the uids that map providers back to
    // candidates are read from `/providers` — once for all of them, not once each.
    expect(harness.applySentIncludeParam()).toBe(false);
    expect(harness.providerUidLookupCount).toBe(1);
    expect(harness.singleProviderFetchCount).toBe(0);
  }, 40000);

  it("links the wizard docs to the GCP organizations tutorial", async () => {
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await harness.mount();
    await harness.chooseGcpOrganizations();

    expect(harness.hasDocsLinkTo(GCP_ORG_DOCS)).toBe(true);
  }, 30000);

  it("nests each project under its discovered folder and renders every folder once", async () => {
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await onboardGcpToSelection(harness);

    // Folder identity is the resource `name`, which is what children carry as
    // `parent`; reading it from any other field flattens the tree.
    expect(harness.countContainerRows("Engineering")).toBe(1);
    expect(harness.countContainerRows("Platform")).toBe(1);
    expect(harness.containerRowUids().sort()).toEqual([
      "folders/1000000001",
      "folders/1000000002",
      GCP_EMPTY_FOLDER,
      GCP_BLOCKED_FOLDER,
    ]);

    expect(
      harness.isCandidateNestedUnder("prod-analytics", "Engineering"),
    ).toBe(true);
    expect(harness.isCandidateNestedUnder("prod-platform", "Platform")).toBe(
      true,
    );
  }, 40000);

  it("prefills a project alias with its display name, never its resource name", async () => {
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await onboardGcpToSelection(harness);

    expect(harness.candidateAliasValue(/prod-analytics/)).toBe(
      "Prod Analytics",
    );
    expect(harness.candidateAliasValue(/prod-analytics/)).not.toMatch(
      /^projects\//,
    );
  }, 40000);

  it("marks a folder with nothing selectable as inert, in project wording", async () => {
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await onboardGcpToSelection(harness);

    // Project-less folders do reach the tree, and clicking them selects nothing —
    // which the row has to say, in GCP's own nouns.
    expect(harness.isContainerInert(GCP_EMPTY_FOLDER_NAME)).toBe(true);
    expect(harness.inertContainerNote(GCP_EMPTY_FOLDER_NAME)).toBe(
      "No projects available to select in this folder.",
    );
    expect(harness.isContainerInert(GCP_BLOCKED_FOLDER_NAME)).toBe(true);

    // A folder holding a ready project stays selectable.
    expect(harness.isContainerInert("Engineering")).toBe(false);
    expect(harness.inertContainerNote("Engineering")).toBeNull();
    expect(harness.usesAccountWording()).toBe(false);
  }, 40000);

  it("still opens an inert folder so its blocked projects are visible", async () => {
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await onboardGcpToSelection(harness);

    expect(
      harness.isCandidateNestedUnder(
        GCP_BLOCKED_FOLDER_PROJECT,
        GCP_BLOCKED_FOLDER_NAME,
      ),
    ).toBe(true);

    // The row collapses and re-expands rather than selecting: an inert folder that
    // could not be opened would never explain itself.
    await harness.clickContainerRow(GCP_BLOCKED_FOLDER_NAME);
    await harness.waitForTransition();
    expect(harness.isCandidateVisible(GCP_BLOCKED_FOLDER_PROJECT)).toBe(false);

    await harness.clickContainerRow(GCP_BLOCKED_FOLDER_NAME);
    await harness.waitForTransition();
    expect(harness.isCandidateVisible(GCP_BLOCKED_FOLDER_PROJECT)).toBe(true);
    expect(harness.hasSelectedProjectCount(2, 2)).toBe(true);
  }, 40000);

  it("keeps a long project id inside its column instead of over the alias input", async () => {
    const harness = new ProvidersPageHarness(
      gcpOnboardingFixture({
        discovery: {
          id: "disc-gcp-1",
          status: DISCOVERY_STATUS_VALUE.SUCCEEDED,
          result: buildGcpDiscoveryResult({ includeLongIdProject: true }),
          error: null,
        },
      }),
    );
    await onboardGcpToSelection(harness);

    // Real layout, not class names: a leaf row that cannot shrink pushes the id
    // over its neighbour instead of ellipsizing.
    expect(harness.candidateRowOverflows(GCP_LONG_PROJECT_ID)).toBe(false);
  }, 40000);

  // These three cases pin how `/schedules/bulk`'s per-provider lists are read: a
  // client looking one level too deep sees no lists and cannot tell them apart.
  it("launches initial scans only for the projects whose schedule was saved", async () => {
    const harness = new ProvidersPageHarness(
      gcpOnboardingFixture({
        scheduleBulk: {
          updated: [GCP_CREATED_PROVIDER_IDS[0]],
          failed: [{ id: GCP_CREATED_PROVIDER_IDS[1], error: "Denied" }],
          shape: "flat",
        },
      }),
    );
    await onboardGcpToSelection(harness);
    await harness.testConnections();
    await harness.waitForProjectsConnected();

    await harness.enableInitialScan();
    await harness.saveScheduleAndLaunch();
    await harness.waitForPartialScheduleSave(1, 1);

    // The reason the API gave must reach the user — a count alone is unactionable.
    expect(harness.hasScheduleFailureReason("Denied")).toBe(true);
    expect(harness.scanLaunchCount).toBe(1);
  }, 40000);

  it("keeps the user on the launch step when no schedule could be saved", async () => {
    const harness = new ProvidersPageHarness(
      gcpOnboardingFixture({
        scheduleBulk: {
          updated: [],
          failed: GCP_CREATED_PROVIDER_IDS.map((id) => ({
            id,
            error: "Denied",
          })),
          shape: "flat",
        },
      }),
    );
    await onboardGcpToSelection(harness);
    await harness.testConnections();
    await harness.waitForProjectsConnected();

    await harness.enableInitialScan();
    await harness.saveScheduleAndLaunch();
    await harness.waitForScheduleSaveFailure();

    expect(harness.hasScheduleFailureReason("Denied")).toBe(true);
    expect(harness.isStillOnLaunchStep()).toBe(true);
    expect(harness.scanLaunchCount).toBe(0);
  }, 40000);

  it("proceeds when the schedule response carries no result lists", async () => {
    // The POST commits each schedule before answering, so an unreadable body must
    // not strand the user on a schedule that already exists.
    const harness = new ProvidersPageHarness(
      gcpOnboardingFixture({
        scheduleBulk: { updated: null, failed: [], shape: "bare" },
      }),
    );
    await onboardGcpToSelection(harness);
    await harness.testConnections();
    await harness.waitForProjectsConnected();

    await harness.enableInitialScan();
    await harness.saveScheduleAndLaunch();
    await harness.waitForLaunchComplete();

    expect(harness.scanLaunchCount).toBe(GCP_CREATED_PROVIDER_IDS.length);
  }, 40000);

  it("sends a projects-only apply payload (no accounts, no organizational units)", async () => {
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await onboardGcpToSelection(harness);

    await harness.testConnections();
    await harness.waitForProjectsConnected();

    const body = await harness.lastRequestBody<ApplyRequestBody>(
      "POST",
      "/apply",
    );
    const attributes = body?.data.attributes;
    expect(attributes?.projects?.map((p) => p.project_id).sort()).toEqual([
      "prod-analytics",
      "prod-platform",
    ]);
    // GCP derives folder ancestors server-side, so no accounts/OUs are ever sent.
    expect(attributes?.accounts).toBeUndefined();
    expect(attributes?.organizational_units).toBeUndefined();
    // No alias was typed, so none is included.
    expect(attributes?.projects?.every((p) => p.alias === undefined)).toBe(
      true,
    );
  }, 40000);

  it("includes an alias only for projects the user renamed", async () => {
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await onboardGcpToSelection(harness);

    await harness.setCandidateAlias(/prod-analytics/, "Analytics Prod");
    await harness.testConnections();
    await harness.waitForProjectsConnected();

    const body = await harness.lastRequestBody<ApplyRequestBody>(
      "POST",
      "/apply",
    );
    const projects = body?.data.attributes.projects ?? [];
    const analytics = projects.find((p) => p.project_id === "prod-analytics");
    const platform = projects.find((p) => p.project_id === "prod-platform");
    expect(analytics?.alias).toBe("Analytics Prod");
    expect(platform?.alias).toBeUndefined();
  }, 40000);

  it("disables blocked projects and excludes them from the selectable count", async () => {
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await onboardGcpToSelection(harness);

    expect(await harness.isCandidateBlocked(/legacy-sandbox/)).toBe(true);

    // Two ready projects, the third (blocked) excluded from the count.
    expect(harness.hasSelectedProjectCount(2, 2)).toBe(true);
    expect(harness.hasSelectedProjectCount(3, 3)).toBe(false);
  }, 40000);

  it("renders a folder as indeterminate when only some descendant projects are selected", async () => {
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await onboardGcpToSelection(harness);

    // Both ready projects start selected → the Engineering folder is fully checked.
    expect(harness.candidateCheckboxState(/Engineering/)).toBe("true");

    // Deselect one descendant project; its ancestor folder goes indeterminate.
    await harness.toggleCandidate(/prod-platform/);
    await harness.waitForSelectedProjectCount(1, 2);
    expect(harness.candidateCheckboxState(/Engineering/)).toBe("mixed");
  }, 40000);

  it("warns before replacing an existing organization credential, then proceeds on confirm", async () => {
    const fixture: OrgFixture = gcpOnboardingFixture({
      organizations: [
        {
          id: "org-gcp-existing",
          orgType: ORGANIZATION_TYPE.GCP,
          name: "Existing GCP Org",
          externalId: GCP_ORG_ID,
          rootExternalId: null,
          providerIds: ["gp-existing-1", "gp-existing-2"],
          nodeIds: [],
          secretId: "secret-gcp-existing",
        },
      ],
    });
    const harness = new ProvidersPageHarness(fixture);
    await authenticateGcpOrg(harness);

    // The credential is replaced only after the user confirms, and the warning
    // states how many onboarded providers that re-authenticates.
    await harness.waitForCredentialReplaceWarning();
    expect(harness.hasCredentialReplaceProviderCount(2)).toBe(true);

    await harness.confirmCredentialReplace();

    // Confirming updates the secret (PATCH) and continues into selection.
    await harness.waitForSelectionTree();
    await harness.waitForProjectSelection();
    await harness.waitForSecretReplace();
  }, 40000);

  it("warns before an apply that overwrites already-onboarded project credentials", async () => {
    const fixture = gcpOnboardingFixture({
      discovery: {
        id: "disc-gcp-1",
        status: DISCOVERY_STATUS_VALUE.SUCCEEDED,
        result: buildGcpDiscoveryResult({
          replaceProjectIds: ["prod-analytics"],
        }),
        error: null,
      },
    });
    const harness = new ProvidersPageHarness(fixture);
    await onboardGcpToSelection(harness);

    await harness.testConnections();

    // Pre-apply warning names the project whose credentials will be overwritten.
    await harness.waitForCredentialReplaceWarning();
    expect(harness.hasApplyOverwriteWarning(1, ["Prod Analytics"])).toBe(true);
    expect(harness.applyCallCount).toBe(0);

    await harness.confirmApplyOverwrite();
    await harness.waitForProjectsConnected();
    expect(harness.applyCallCount).toBe(1);
  }, 40000);

  it("surfaces a failed discovery and retries with a fresh discovery", async () => {
    const fixture = gcpOnboardingFixture({
      discovery: {
        id: "disc-gcp-1",
        status: DISCOVERY_STATUS_VALUE.FAILED,
        result: {},
        error: "Service account lacks organization permissions",
      },
    });
    const harness = new ProvidersPageHarness(fixture);
    await authenticateGcpOrg(harness);

    await harness.waitForDiscoveryFailure();
    await harness.waitForDiscoveryCount(1);

    // Retry triggers a brand-new discovery, not a resumed poll.
    await harness.retryDiscovery();
    await harness.waitForDiscoveryCount(2);
  }, 40000);
});

describe("GCP Organizations connect step (Phase 2)", () => {
  it("gates the GCP Organization method behind the cloud upgrade in OSS builds", async ({
    seedRuntimeConfig,
  }) => {
    seedRuntimeConfig({ cloudEnabled: false });
    const harness = new ProvidersPageHarness(gcpOnboardingFixture());
    await harness.mount();

    await harness.selectProviderType(/Google Cloud Platform/);
    await harness.waitForMethodStep();

    // Choosing the org method must NOT start the flow in OSS.
    await harness.chooseMethod(/Add Multiple Projects With GCP Organization/);
    await harness.waitForMethodStep();
    expect(harness.hasOrganizationSetupStep()).toBe(false);
  }, 30000);
});

describe("GCP Organizations providers page (Phase 2)", () => {
  it("deletes a GCP folder with kind-aware copy and deletion-task polling", async () => {
    const harness = new ProvidersPageHarness(mixedHierarchyFixture());
    await harness.mount({ openWizard: false });
    await harness.waitForNodeGroup(GCP_FOLDER_NAME);

    // GCP container nodes are "folders", not "organizational units".
    await harness.openDeleteFolderFor(GCP_FOLDER_NAME);

    await harness.waitForDeleteConfirmation();
    expect(harness.hasDeleteWarningFor("folder")).toBe(true);

    await harness.confirmDelete();

    await harness.waitForNodeDelete(GCP_FOLDER_NODE_ID);
    // The polled task completes when the per-provider deletions are dispatched, so
    // the copy may report acceptance and never that the folder is gone.
    await harness.waitForTaskPoll("del-task-");
    await harness.waitForDeletionAccepted();
    expect(harness.claimsDeletionFinished()).toBe(false);
  }, 30000);

  it("reports a failed deletion task instead of a false success", async () => {
    const harness = new ProvidersPageHarness(
      mixedHierarchyFixture({ deletionTaskState: "failed" }),
    );
    await harness.mount({ openWizard: false });
    await harness.waitForOrganizationRow(GCP_ORG_NAME);

    await harness.openDeleteFor(GCP_ORG_NAME);

    await harness.waitForDeleteConfirmation();
    expect(harness.hasCascadeWarning(2)).toBe(true);

    await harness.confirmDelete();

    // A failed task is reported as not completed, and the hierarchy refetched so
    // the restored subtree reappears.
    await harness.waitForDeletionFailure();
  }, 30000);
});
