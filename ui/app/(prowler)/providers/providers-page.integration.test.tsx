import { describe, expect, it } from "vitest";

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
  harness.mount();
  await harness.chooseAwsOrganizations();
  await harness.fillAwsOrgDetails(AWS_ORG_ID, "My AWS Org");
  await harness.clickPrimary(/Next/);
  await harness.fillAwsAccess({ ouId: "r-aws0", roleArn: AWS_ROLE_ARN });
  await harness.clickPrimary(/Authenticate/);
  await harness.waitForSelectionTree();
  await harness.waitForText(/of \d+ accounts selected/, 15000);
}

describe("AWS Organizations onboarding (baseline)", () => {
  it("completes the happy path: setup → discovery → selection → apply → connect → launch", async () => {
    const harness = new ProvidersPageHarness(awsOnboardingFixture());
    await onboardToSelection(harness);

    await harness.testConnections();
    await harness.waitForText(/Accounts Connected!/, 20000);

    expect(harness.containsText(/Accounts Connected!/)).toBe(true);
    expect(harness.applyCallCount).toBe(1);
  }, 40000);

  it("disables blocked accounts and excludes them from the selectable count", async () => {
    const harness = new ProvidersPageHarness(awsOnboardingFixture());
    await onboardToSelection(harness);

    const blocked = await harness.waitFor(() =>
      harness.treeItemByText(/333333333333/),
    );
    expect(blocked.getAttribute("aria-disabled")).toBe("true");

    await harness.waitForText(/2 of 2 accounts selected/, 15000);
    expect(harness.containsText(/3 of 3 accounts selected/)).toBe(false);
  }, 40000);

  it("retries only the failed connections without re-applying", async () => {
    const harness = new ProvidersPageHarness(partialConnectionFixture());
    await onboardToSelection(harness);

    await harness.testConnections();
    await harness.waitForConnectionErrorAlert();
    await harness.waitFor(() => harness.connectionCallCount === 2, 20000);
    expect(harness.applyCallCount).toBe(1);

    await harness.testConnections();
    await harness.waitFor(() => harness.connectionCallCount === 3, 20000);
    expect(harness.applyCallCount).toBe(1);
  }, 60000);

  it("re-applies when the selection changes after an apply", async () => {
    const harness = new ProvidersPageHarness(partialConnectionFixture());
    await onboardToSelection(harness);

    await harness.testConnections();
    await harness.waitForConnectionErrorAlert();
    expect(harness.applyCallCount).toBe(1);

    await harness.clickBack();
    await harness.toggleCandidate(/222222222222/);
    await harness.testConnections();
    await harness.waitFor(() => harness.applyCallCount === 2, 20000);
  }, 60000);

  it("allows skipping validation once at least one account connected", async () => {
    const harness = new ProvidersPageHarness(partialConnectionFixture());
    await onboardToSelection(harness);

    await harness.testConnections();
    await harness.waitForConnectionErrorAlert();

    await harness.skipValidation();
    await harness.waitForText(/Accounts Connected!|ready to Scan/, 20000);
  }, 60000);
});

describe("AWS Organizations providers page (baseline)", () => {
  it("groups providers under their organization and OUs with kind-driven labels", async () => {
    const harness = new ProvidersPageHarness(awsHierarchyFixture());
    harness.mount({ openWizard: false });

    // Organization group row + its OU sub-groups (expanded by default in cloud).
    await harness.waitForText(/My AWS Organization/);
    await harness.waitForRow(/Production/);
    await harness.waitForRow(/Sandbox/);

    // Node group rows are labelled by kind, not by ID prefix.
    expect(harness.containsText(/Organizational Unit/)).toBe(true);
    // Organization row surfaces its total provider count.
    expect(harness.containsText(/3 Providers/)).toBe(true);

    // Providers render nested under their OU, addressed by alias.
    expect(harness.rowByText(/prod-web/)).not.toBeNull();
    expect(harness.rowByText(/prod-api/)).not.toBeNull();
    expect(harness.rowByText(/sandbox-1/)).not.toBeNull();
  }, 30000);

  it("edits the organization name via the inline modal (PATCH)", async () => {
    const harness = new ProvidersPageHarness(awsHierarchyFixture());
    harness.mount({ openWizard: false });
    await harness.waitForText(/My AWS Organization/);

    await harness.openRowActionsFor(/My AWS Organization/);
    await harness.clickMenuItem(/Edit Organization Name/);

    // The edit-name affordance is an inline modal (not the wizard) today.
    await harness.waitForText(
      /If left blank, Prowler will use the name stored in AWS/,
    );
    await harness.fillEditName("Renamed AWS Org");
    await harness.clickButton(/^\s*Save\s*$/);

    await harness.waitFor(
      () =>
        harness.countRequests(
          "PATCH",
          `/organizations/${AWS_HIERARCHY_ORG_ID}`,
        ) === 1,
      15000,
    );
  }, 30000);

  it("re-enters the wizard at the authentication step to update credentials", async () => {
    const harness = new ProvidersPageHarness(awsHierarchyFixture());
    harness.mount({ openWizard: false });
    await harness.waitForText(/My AWS Organization/);

    await harness.openRowActionsFor(/My AWS Organization/);
    await harness.clickMenuItem(/Update Credentials/);

    // Opens the org wizard directly on the AWS authentication (access) phase.
    await harness.waitForText(
      /Amazon Web Services \(AWS\) \/ Authentication Details/,
    );
    expect(harness.buttonByText(/Authenticate/)).not.toBeNull();
    // Edit-credentials re-entry skips the details step, so Back is hidden.
    expect(harness.buttonByText(/^\s*Back\s*$/)).toBeNull();
  }, 30000);

  it("deletes an organization as a fire-and-forget request (no task polling)", async () => {
    const harness = new ProvidersPageHarness(awsHierarchyFixture());
    harness.mount({ openWizard: false });
    await harness.waitForText(/My AWS Organization/);

    await harness.openRowActionsFor(/My AWS Organization/);
    await harness.clickMenuItem(/Delete Organization/);

    // Cascade confirmation dialog.
    await harness.waitForText(/Are you absolutely sure/);
    expect(harness.containsText(/permanently delete this organization/)).toBe(
      true,
    );

    await harness.clickButton(/^\s*Delete\s*$/);

    await harness.waitFor(
      () =>
        harness.countRequests(
          "DELETE",
          `/organizations/${AWS_HIERARCHY_ORG_ID}`,
        ) === 1,
      15000,
    );
    // Current behaviour: single DELETE, no deletion-task polling (Phase 2 adds it).
    expect(harness.countRequests("GET", "/tasks/")).toBe(0);
  }, 30000);
});
