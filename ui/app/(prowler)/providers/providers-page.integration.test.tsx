import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import {
  awsHierarchyFixture,
  awsOnboardingFixture,
  type OrgFixture,
} from "@/__tests__/msw/handlers/organizations.fixtures";

import { ProvidersPageHarness } from "./providers-page.harness";

const AWS_ORG_ID = "o-aws0abcdef";
const AWS_ROLE_ARN = "arn:aws:iam::111111111111:role/ProwlerScan";
/** The organization id seeded by `awsHierarchyFixture`. */
const AWS_HIERARCHY_ORG_ID = "org-aws-1";
const AWS_ORG_NAME = "My AWS Organization";
/** A world where one of the two ready accounts fails its connection test. */
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

describe("AWS Organizations onboarding (baseline)", () => {
  it("completes the happy path: setup → discovery → selection → apply → connect → launch", async () => {
    const harness = new ProvidersPageHarness(awsOnboardingFixture());
    await onboardToSelection(harness);

    await harness.testConnections();
    await harness.waitForAccountsConnected();

    expect(harness.applyCallCount).toBe(1);

    // Drive the final action: save the schedules for both created providers and
    // launch an initial scan for each.
    await harness.enableInitialScan();
    await harness.saveScheduleAndLaunch();
    await harness.waitForLaunchComplete();

    expect(harness.scheduleBulkCallCount).toBe(1);
    expect(harness.organizationBulkScanCallCount).toBe(1);
  }, 60000);

  it("disables blocked accounts and excludes them from the selectable count", async () => {
    const harness = new ProvidersPageHarness(awsOnboardingFixture());
    await onboardToSelection(harness);

    expect(await harness.isAccountBlocked("333333333333")).toBe(true);

    await harness.waitForSelectedCount(2, 2);
    expect(harness.hasSelectedCount(3, 3)).toBe(false);
  }, 40000);

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
    // Given — one account connects on the first read, the other stays running.
    const harness = new ProvidersPageHarness(
      awsOnboardingFixture({
        connectionByUid: {
          "111111111111": { connected: true },
          "222222222222": { connected: true, executingPolls: 2 },
        },
      }),
    );
    await onboardToSelection(harness);

    // When
    await harness.testConnections();
    await harness.waitForCandidateConnectionState(/111111111111/, "success");

    // Then — the finished account reports while the slow one is still testing.
    expect(harness.candidateConnectionState(/222222222222/)).toBe("testing");

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

describe("AWS Organizations providers page (baseline)", () => {
  it("groups providers under their organization and OUs with kind-driven labels", async () => {
    const harness = new ProvidersPageHarness(awsHierarchyFixture());
    await harness.mount({ openWizard: false });

    // Organization group row + its OU sub-groups (expanded by default in cloud).
    await harness.waitForOrganizationRow(AWS_ORG_NAME);
    await harness.waitForNodeGroup("Production");
    await harness.waitForNodeGroup("Sandbox");

    // Node group rows are labelled by kind, not by ID prefix.
    expect(harness.hasNodeKindLabel("Organizational Unit")).toBe(true);
    // Organization row surfaces its total provider count.
    expect(harness.hasProviderCount(3)).toBe(true);

    // Providers render nested under their OU, addressed by alias.
    expect(harness.hasProviderRow("prod-web")).toBe(true);
    expect(harness.hasProviderRow("prod-api")).toBe(true);
    expect(harness.hasProviderRow("sandbox-1")).toBe(true);

    // Tripwire: the rows above came from real requests, so a loader that stops
    // fetching the hierarchy (either route) fails here instead of staying green
    // on harness-supplied data.
    expect(harness.organizationFetchCount).toBeGreaterThan(0);
    expect(harness.hierarchyFetchCount).toBeGreaterThan(0);
  }, 30000);

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

    // Opens the org wizard directly on the AWS authentication (access) phase.
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

    // Cascade confirmation dialog, stating the affected provider count.
    await harness.waitForDeleteConfirmation();
    expect(harness.hasDeleteWarning()).toBe(true);
    expect(harness.hasCascadeWarning(3)).toBe(true);

    await harness.confirmDelete();

    await harness.waitForOrganizationDelete(AWS_HIERARCHY_ORG_ID);
    // Deletion is a 202 + task: nothing is reported until the UI has polled it.
    await harness.waitForTaskPoll();
  }, 30000);

  it("renders a flat provider list (no org/OU grouping) on-prem", async ({
    seedRuntimeConfig,
  }) => {
    seedRuntimeConfig({ cloudEnabled: false });
    const harness = new ProvidersPageHarness(awsHierarchyFixture());
    await harness.mount({ openWizard: false });

    // Providers still render, but ungrouped: no organization row, no OU labels.
    await harness.waitForProviderRow("prod-web");
    expect(harness.hasProviderRow("prod-api")).toBe(true);
    expect(harness.hasProviderRow("sandbox-1")).toBe(true);
    expect(harness.hasOrganizationRow(AWS_ORG_NAME)).toBe(false);
    expect(harness.hasNodeKindLabel("Organizational Unit")).toBe(false);
    // On-prem never asks for the organization hierarchy at all.
    expect(harness.hierarchyFetchCount).toBe(0);
  }, 30000);
});
