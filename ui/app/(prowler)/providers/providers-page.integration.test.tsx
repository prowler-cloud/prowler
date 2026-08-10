import { describe, expect } from "vitest";

// One integration file per real page: the whole providers page lives here.
// `it` comes from the fixtures module for its auto `seedRuntimeConfig` — grouping
// is cloud-only, so the runtime-config island must exist before mounting.
import { it } from "@/__tests__/fixtures";
import { HIERARCHY_READ_FAILURE } from "@/__tests__/msw/handlers/organizations";
import {
  awsHierarchyFixture,
  awsOnboardingFixture,
  buildGcpDiscoveryResult,
  displayOnlyOrgHierarchyFixture,
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

const AWS_ORG_ID = "o-aws0abcdef";
const AWS_ROLE_ARN = "arn:aws:iam::111111111111:role/ProwlerScan";
/** The organization id seeded by `awsHierarchyFixture`. */
const AWS_HIERARCHY_ORG_ID = "org-aws-1";
const AWS_ORG_NAME = "My AWS Organization";
const partialConnectionFixture = (): OrgFixture =>
  awsOnboardingFixture({
    connectionByUid: {
      "111111111111": { connected: true },
      "222222222222": { connected: false, error: "Access denied" },
    },
  });

/** Drive a fresh AWS org onboarding up to the populated selection tree. */
async function onboardToSelection(
  harness: ProvidersPageHarness,
): Promise<void> {
  await harness.mount();
  await harness.chooseAwsOrganizations();
  await harness.fillAwsOrgDetails(AWS_ORG_ID, "My AWS Org");
  await harness.submitOrganizationDetails();
  await harness.fillAwsAccess({ ouId: "r-aws0", roleArn: AWS_ROLE_ARN });
  await harness.authenticate();
  await harness.waitForSelectionTree();
  await harness.waitForAccountSelection();
}

const VALID_SA_KEY = JSON.stringify({
  type: "service_account",
  project_id: "prowler-scan",
  private_key_id: "abcdef",
  client_email: "prowler@prowler-scan.iam.gserviceaccount.com",
});

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

interface ApplyProjectRequest {
  project_id: string;
  alias?: string;
}

interface ApplyRequestAttributes {
  projects?: ApplyProjectRequest[];
  accounts?: unknown;
  organizational_units?: unknown;
}

interface ApplyRequestData {
  attributes: ApplyRequestAttributes;
}

interface ApplyRequestBody {
  data: ApplyRequestData;
}

describe("Organization onboarding wizard", () => {
  describe("AWS Organizations", () => {
    describe("Full onboarding run", () => {
      it("completes the happy path: setup → discovery → selection → apply → connect → launch", async () => {
        const harness = new ProvidersPageHarness(awsOnboardingFixture());
        await onboardToSelection(harness);

        await harness.testConnections();
        await harness.waitForAccountsConnected();

        expect(harness.applyCallCount).toBe(1);

        await harness.enableInitialScan();
        await harness.saveScheduleAndLaunch();
        await harness.waitForLaunchComplete();

        expect(harness.scheduleBulkCallCount).toBe(1);
        expect(harness.organizationBulkScanCallCount).toBe(1);
      }, 60000);
    });

    describe("Account selection", () => {
      it("disables blocked accounts and excludes them from the selectable count", async () => {
        const harness = new ProvidersPageHarness(awsOnboardingFixture());
        await onboardToSelection(harness);

        expect(await harness.isAccountBlocked("333333333333")).toBe(true);

        await harness.waitForSelectedCount(2, 2);
        expect(harness.hasSelectedCount(3, 3)).toBe(false);
      }, 40000);
    });

    describe("Connection testing", () => {
      it("retries only the failed connections without re-applying", async () => {
        const harness = new ProvidersPageHarness(partialConnectionFixture());
        await onboardToSelection(harness);

        await harness.testConnections();
        await harness.waitForConnectionError();
        await harness.waitForConnectionAttempts(2);
        expect(harness.applyCallCount).toBe(1);

        await harness.testConnections();
        await harness.waitForConnectionAttempts(3);
        expect(harness.applyCallCount).toBe(1);
      }, 60000);

      it("settles each account the moment its own test finishes", async () => {
        const harness = new ProvidersPageHarness(
          awsOnboardingFixture({
            connectionByUid: {
              "111111111111": { connected: true },
              "222222222222": { connected: true, executingPolls: 2 },
            },
          }),
        );
        await onboardToSelection(harness);

        await harness.testConnections();
        await harness.waitForCandidateConnectionState(
          /111111111111/,
          "success",
        );

        expect(harness.candidateConnectionState(/222222222222/)).toBe(
          "testing",
        );

        await harness.waitForAccountsConnected();
      }, 60000);

      it("re-applies when the selection changes after an apply", async () => {
        const harness = new ProvidersPageHarness(partialConnectionFixture());
        await onboardToSelection(harness);

        await harness.testConnections();
        await harness.waitForConnectionError();
        expect(harness.applyCallCount).toBe(1);

        await harness.goBack();
        await harness.toggleAccount("222222222222");
        await harness.testConnections();
        await harness.waitForApplyCount(2);
      }, 60000);

      it("allows skipping validation once at least one account connected", async () => {
        const harness = new ProvidersPageHarness(partialConnectionFixture());
        await onboardToSelection(harness);

        await harness.testConnections();
        await harness.waitForConnectionError();

        await harness.skipValidation();
        await harness.waitForReadyToScan();
      }, 60000);
    });
  });

  describe("GCP Organizations", () => {
    describe("Full onboarding run", () => {
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
    });

    describe("Wizard entry", () => {
      it("links the wizard docs to the GCP organizations tutorial", async () => {
        const harness = new ProvidersPageHarness(gcpOnboardingFixture());
        await harness.mount();
        await harness.chooseGcpOrganizations();

        expect(harness.hasDocsLinkTo(GCP_ORG_DOCS)).toBe(true);
      }, 30000);

      it("gates the GCP Organization method behind the cloud upgrade in OSS builds", async ({
        seedRuntimeConfig,
      }) => {
        seedRuntimeConfig({ cloudEnabled: false });
        const harness = new ProvidersPageHarness(gcpOnboardingFixture());
        await harness.mount();

        await harness.selectProviderType(/Google Cloud Platform/);
        await harness.waitForMethodStep();

        await harness.chooseMethod(
          /Add Multiple Projects With GCP Organization/,
        );
        await harness.waitForMethodStep();
        expect(harness.hasOrganizationSetupStep()).toBe(false);
      }, 30000);
    });

    describe("Project selection", () => {
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
        expect(
          harness.isCandidateNestedUnder("prod-platform", "Platform"),
        ).toBe(true);
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

        // A project-less folder still reaches the tree, and has to say so in GCP nouns.
        expect(harness.isContainerInert(GCP_EMPTY_FOLDER_NAME)).toBe(true);
        expect(harness.inertContainerNote(GCP_EMPTY_FOLDER_NAME)).toBe(
          "No projects available to select in this folder.",
        );
        expect(harness.isContainerInert(GCP_BLOCKED_FOLDER_NAME)).toBe(true);

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
        expect(harness.isCandidateVisible(GCP_BLOCKED_FOLDER_PROJECT)).toBe(
          false,
        );

        await harness.clickContainerRow(GCP_BLOCKED_FOLDER_NAME);
        await harness.waitForTransition();
        expect(harness.isCandidateVisible(GCP_BLOCKED_FOLDER_PROJECT)).toBe(
          true,
        );
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

        // Real layout boxes, not class names: an unshrinkable row pushes the id out.
        expect(harness.candidateRowOverflows(GCP_LONG_PROJECT_ID)).toBe(false);
      }, 40000);

      it("disables blocked projects and excludes them from the selectable count", async () => {
        const harness = new ProvidersPageHarness(gcpOnboardingFixture());
        await onboardGcpToSelection(harness);

        expect(await harness.isCandidateBlocked(/legacy-sandbox/)).toBe(true);

        expect(harness.hasSelectedProjectCount(2, 2)).toBe(true);
        expect(harness.hasSelectedProjectCount(3, 3)).toBe(false);
      }, 40000);

      it("renders a folder as indeterminate when only some descendant projects are selected", async () => {
        const harness = new ProvidersPageHarness(gcpOnboardingFixture());
        await onboardGcpToSelection(harness);

        expect(harness.candidateCheckboxState(/Engineering/)).toBe("true");

        await harness.toggleCandidate(/prod-platform/);
        await harness.waitForSelectedProjectCount(1, 2);
        expect(harness.candidateCheckboxState(/Engineering/)).toBe("mixed");
      }, 40000);
    });

    describe("Apply payload", () => {
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
        const analytics = projects.find(
          (p) => p.project_id === "prod-analytics",
        );
        const platform = projects.find((p) => p.project_id === "prod-platform");
        expect(analytics?.alias).toBe("Analytics Prod");
        expect(platform?.alias).toBeUndefined();
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
    });

    describe("Credential conflicts", () => {
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

        await harness.waitForCredentialReplaceWarning();
        expect(harness.hasCredentialReplaceProviderCount(2)).toBe(true);

        await harness.confirmCredentialReplace();

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

        await harness.waitForCredentialReplaceWarning();
        expect(harness.hasApplyOverwriteWarning(1, ["Prod Analytics"])).toBe(
          true,
        );
        expect(harness.applyCallCount).toBe(0);

        await harness.confirmApplyOverwrite();
        await harness.waitForProjectsConnected();
        expect(harness.applyCallCount).toBe(1);
      }, 40000);
    });

    describe("Discovery failures", () => {
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

    describe("Launch and scheduling", () => {
      it("launches the organization after a partial schedule save", async () => {
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
        expect(harness.organizationBulkScanCallCount).toBe(1);
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
        expect(harness.organizationBulkScanCallCount).toBe(0);
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

        expect(harness.organizationBulkScanCallCount).toBe(1);
      }, 40000);
    });
  });
});

describe("Providers page", () => {
  describe("Organization hierarchy display", () => {
    describe("AWS Organizations", () => {
      it("groups providers under their organization and OUs with kind-driven labels", async () => {
        const harness = new ProvidersPageHarness(awsHierarchyFixture());
        await harness.mount({ openWizard: false });

        await harness.waitForOrganizationRow(AWS_ORG_NAME);
        await harness.waitForNodeGroup("Production");
        await harness.waitForNodeGroup("Sandbox");

        expect(harness.hasNodeKindLabel("Organizational Unit")).toBe(true);
        expect(harness.hasProviderCount(3)).toBe(true);

        expect(harness.hasProviderRow("prod-web")).toBe(true);
        expect(harness.hasProviderRow("prod-api")).toBe(true);
        expect(harness.hasProviderRow("sandbox-1")).toBe(true);

        // Tripwire: a loader that stops fetching the hierarchy (either route) fails
        // here instead of staying green on harness-supplied data.
        expect(harness.organizationFetchCount).toBeGreaterThan(0);
        expect(harness.hierarchyFetchCount).toBeGreaterThan(0);
      }, 30000);
    });

    describe("Mixed AWS + GCP", () => {
      it("groups both organizations, labelling nodes by kind (Organizational Unit vs Folder)", async () => {
        const harness = new ProvidersPageHarness(mixedHierarchyFixture());
        await harness.mount({ openWizard: false });

        await harness.waitForOrganizationRow("My AWS Organization");
        await harness.waitForOrganizationRow("My GCP Organization");

        await harness.waitForNodeGroup("Production");
        await harness.waitForNodeGroup("Sandbox");
        await harness.waitForNodeGroup("Engineering");
        await harness.waitForNodeGroup("Platform");

        // Labels are kind-driven, never ID-prefix-driven.
        expect(harness.hasNodeKindLabel("Organizational Unit")).toBe(true);
        expect(harness.hasNodeKindLabel("Folder")).toBe(true);

        expect(harness.hasProviderCount(3)).toBe(true);
        expect(harness.hasProviderCount(2)).toBe(true);

        expect(harness.hasProviderRow("prod-web")).toBe(true);
        expect(harness.hasProviderRow("sandbox-1")).toBe(true);
        expect(harness.hasProviderRow("Prod Analytics")).toBe(true);
        expect(harness.hasProviderRow("Prod Platform")).toBe(true);

        // Tripwire: those rows came from a real fetch of the canonical route.
        expect(harness.hierarchyFetchCount).toBeGreaterThan(0);
      }, 30000);
    });

    describe("Organization type without an onboarding flow", () => {
      it("groups it with its own wording and offers no wizard re-entry", async () => {
        const harness = new ProvidersPageHarness(
          displayOnlyOrgHierarchyFixture(),
        );
        await harness.mount({ openWizard: false });

        // Grouping is display-driven, so the organization still renders as a group.
        await harness.waitForOrganizationRow("Contoso Tenant");
        expect(harness.hasProviderRow("contoso-prod")).toBe(true);

        expect(harness.hasNodeKindLabel("Organizational Unit")).toBe(false);

        // The wizard only exists for onboardable types; renaming is a plain PATCH.
        const actions = await harness.actionLabelsFor("Contoso Tenant");
        expect(actions).toContain("Edit Organization Name");
        expect(actions).not.toContain("Update Credentials");
      }, 30000);
    });

    describe("On-prem builds", () => {
      it("renders a flat provider list (no org/OU grouping) on-prem", async ({
        seedRuntimeConfig,
      }) => {
        seedRuntimeConfig({ cloudEnabled: false });
        const harness = new ProvidersPageHarness(awsHierarchyFixture());
        await harness.mount({ openWizard: false });

        await harness.waitForProviderRow("prod-web");
        expect(harness.hasProviderRow("prod-api")).toBe(true);
        expect(harness.hasProviderRow("sandbox-1")).toBe(true);
        expect(harness.hasOrganizationRow(AWS_ORG_NAME)).toBe(false);
        expect(harness.hasNodeKindLabel("Organizational Unit")).toBe(false);
        // On-prem never asks for the organization hierarchy at all.
        expect(harness.hierarchyFetchCount).toBe(0);
      }, 30000);
    });

    describe("Degraded hierarchy reads", () => {
      it("shows a non-blocking notice and keeps providers listed flat when hierarchy is unavailable", async () => {
        const harness = new ProvidersPageHarness(awsHierarchyFixture());
        await harness.mount({
          openWizard: false,
          hierarchyFailure: HIERARCHY_READ_FAILURE.ALL,
        });

        await harness.waitForDegradedHierarchyNotice();
        expect(harness.hasUngroupedProvidersNotice()).toBe(true);

        expect(harness.hasProviderRow("prod-web")).toBe(true);
        expect(harness.hasOrganizationRow("My AWS Organization")).toBe(false);
      }, 30000);

      it("degrades the same way when only the node read fails", async () => {
        // AWS accounts hang off the OUs, so the organization's own `providers`
        // relationship is empty and its row drops out along with the nodes.
        const harness = new ProvidersPageHarness(awsHierarchyFixture());
        await harness.mount({
          openWizard: false,
          hierarchyFailure: HIERARCHY_READ_FAILURE.NODES,
        });

        await harness.waitForDegradedHierarchyNotice();
        expect(harness.hasUngroupedProvidersNotice()).toBe(true);

        await harness.waitForProviderRow("prod-web");
        expect(harness.hasProviderRow("sandbox-1")).toBe(true);
        expect(harness.hasOrganizationRow("My AWS Organization")).toBe(false);
        expect(harness.hasNodeKindLabel("Organizational Unit")).toBe(false);
      }, 30000);

      it("shows no notice when the hierarchy is available", async () => {
        const harness = new ProvidersPageHarness(awsHierarchyFixture());
        await harness.mount({ openWizard: false });

        await harness.waitForOrganizationRow("My AWS Organization");
        expect(harness.hasDegradedHierarchyNotice()).toBe(false);
      }, 30000);
    });
  });

  describe("Organization management actions", () => {
    describe("AWS Organizations", () => {
      it("edits the organization name via the inline modal (PATCH)", async () => {
        const harness = new ProvidersPageHarness(awsHierarchyFixture());
        await harness.mount({ openWizard: false });
        await harness.waitForOrganizationRow(AWS_ORG_NAME);

        await harness.openEditNameFor(AWS_ORG_NAME);

        // The edit-name affordance is an inline modal (not the wizard) today.
        await harness.waitForEditNameModal();
        await harness.fillEditName("Renamed AWS Org");
        await harness.saveName();

        await harness.waitForOrganizationRename(AWS_HIERARCHY_ORG_ID);
      }, 30000);

      it("re-enters the wizard at the authentication step to update credentials", async () => {
        const harness = new ProvidersPageHarness(awsHierarchyFixture());
        await harness.mount({ openWizard: false });
        await harness.waitForOrganizationRow(AWS_ORG_NAME);

        await harness.openUpdateCredentialsFor(AWS_ORG_NAME);

        await harness.waitForAuthenticationStep();
        expect(harness.hasAuthenticateButton()).toBe(true);
        // Edit-credentials re-entry skips the details step, so Back is hidden.
        expect(harness.hasBackButton()).toBe(false);
      }, 30000);

      it("deletes an organization with a cascade warning and deletion-task polling", async () => {
        const harness = new ProvidersPageHarness(awsHierarchyFixture());
        await harness.mount({ openWizard: false });
        await harness.waitForOrganizationRow(AWS_ORG_NAME);

        await harness.openDeleteFor(AWS_ORG_NAME);

        await harness.waitForDeleteConfirmation();
        expect(harness.hasDeleteWarning()).toBe(true);
        expect(harness.hasCascadeWarning(3)).toBe(true);

        await harness.confirmDelete();

        await harness.waitForOrganizationDelete(AWS_HIERARCHY_ORG_ID);
        // Deletion is a 202 + task: nothing is reported until the UI has polled it.
        await harness.waitForTaskPoll();
      }, 30000);
    });

    describe("GCP Organizations", () => {
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

        await harness.waitForDeletionFailure();
      }, 30000);
    });

    describe("Across organization types", () => {
      it("offers wizard re-entry to every organization type with a setup form", async () => {
        const harness = new ProvidersPageHarness(mixedHierarchyFixture());
        await harness.mount({ openWizard: false });

        await harness.waitForOrganizationRow("My GCP Organization");

        // Every type with a setup form offers "Update Credentials".
        const actions = await harness.actionLabelsFor("My GCP Organization");
        expect(actions).toContain("Edit Organization Name");
        expect(actions).toContain("Update Credentials");

        const awsActions = await harness.actionLabelsFor("My AWS Organization");
        expect(awsActions).toContain("Update Credentials");
      }, 30000);
    });
  });
});
