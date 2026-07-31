import { describe, expect } from "vitest";

// The extended `it` carries the auto `seedRuntimeConfig` fixture — grouping is
// cloud-only, so the runtime-config island must exist before mounting.
import { it } from "@/__tests__/fixtures";
import { HIERARCHY_READ_FAILURE } from "@/__tests__/msw/handlers/organizations";
import {
  awsHierarchyFixture,
  displayOnlyOrgHierarchyFixture,
  mixedHierarchyFixture,
} from "@/__tests__/msw/handlers/organizations.fixtures";

import { ProvidersPageHarness } from "./providers-page.harness";

// Phase 1 new-behavior coverage (the Phase 0 AWS baseline suite stays untouched):
// the providers page now consumes the canonical organization-nodes contract for
// BOTH organization types, deriving container labels from node `kind`, and
// surfaces an explicit notice when the hierarchy fetch degrades.

describe("Providers page — mixed AWS + GCP hierarchy display", () => {
  it("groups both organizations, labelling nodes by kind (Organizational Unit vs Folder)", async () => {
    const harness = new ProvidersPageHarness(mixedHierarchyFixture());
    await harness.mount({ openWizard: false });

    // Both organizations render as top-level groups.
    await harness.waitForOrganizationRow("My AWS Organization");
    await harness.waitForOrganizationRow("My GCP Organization");

    // AWS organizational units and GCP folders both render as node groups.
    await harness.waitForNodeGroup("Production");
    await harness.waitForNodeGroup("Sandbox");
    await harness.waitForNodeGroup("Engineering");
    await harness.waitForNodeGroup("Platform");

    // Container labels are kind-driven, never ID-prefix-driven: AWS nodes read
    // "Organizational Unit", GCP nodes read "Folder".
    expect(harness.hasNodeKindLabel("Organizational Unit")).toBe(true);
    expect(harness.hasNodeKindLabel("Folder")).toBe(true);

    // Per-organization provider counts.
    expect(harness.hasProviderCount(3)).toBe(true);
    expect(harness.hasProviderCount(2)).toBe(true);

    // Providers of both types render nested under their nodes, by alias.
    expect(harness.hasProviderRow("prod-web")).toBe(true);
    expect(harness.hasProviderRow("sandbox-1")).toBe(true);
    expect(harness.hasProviderRow("Prod Analytics")).toBe(true);
    expect(harness.hasProviderRow("Prod Platform")).toBe(true);

    // Tripwire: those rows came from a real fetch of the canonical route.
    expect(harness.hierarchyFetchCount).toBeGreaterThan(0);
  }, 30000);

  it("offers wizard re-entry to every organization type with a setup form", async () => {
    const harness = new ProvidersPageHarness(mixedHierarchyFixture());
    await harness.mount({ openWizard: false });

    await harness.waitForOrganizationRow("My GCP Organization");

    // GCP now owns a setup form, so "Update Credentials" re-enters the wizard on
    // it. Renaming is a plain PATCH either way.
    const actions = await harness.actionLabelsFor("My GCP Organization");
    expect(actions).toContain("Edit Organization Name");
    expect(actions).toContain("Update Credentials");

    // The AWS organization in the same table keeps it.
    const awsActions = await harness.actionLabelsFor("My AWS Organization");
    expect(awsActions).toContain("Update Credentials");
  }, 30000);
});

describe("Providers page — organization type without an onboarding flow", () => {
  it("groups it with its own wording and offers no wizard re-entry", async () => {
    const harness = new ProvidersPageHarness(displayOnlyOrgHierarchyFixture());
    await harness.mount({ openWizard: false });

    // Grouping is display-driven, so the organization still renders as a group.
    await harness.waitForOrganizationRow("Contoso Tenant");
    expect(harness.hasProviderRow("contoso-prod")).toBe(true);

    // It never inherits AWS wording.
    expect(harness.hasNodeKindLabel("Organizational Unit")).toBe(false);

    // Credential updates re-enter the organization wizard, which only exists for
    // onboardable types; renaming is a plain PATCH and stays available.
    const actions = await harness.actionLabelsFor("Contoso Tenant");
    expect(actions).toContain("Edit Organization Name");
    expect(actions).not.toContain("Update Credentials");
  }, 30000);
});

describe("Providers page — degraded hierarchy view", () => {
  it("shows a non-blocking notice and keeps providers listed flat when hierarchy is unavailable", async () => {
    const harness = new ProvidersPageHarness(awsHierarchyFixture());
    await harness.mount({
      openWizard: false,
      hierarchyFailure: HIERARCHY_READ_FAILURE.ALL,
    });

    await harness.waitForDegradedHierarchyNotice();
    expect(harness.hasUngroupedProvidersNotice()).toBe(true);

    // Providers are still present despite grouping being unavailable, and no
    // organization group row survives the failed hierarchy fetch.
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
