import { beforeEach, describe, expect, it } from "vitest";

import {
  AwsOrgHierarchy,
  NODE_KIND,
  ORGANIZATION_TYPE,
} from "@/types/organizations";

import { useOrgSetupStore } from "./store";

const hierarchy: AwsOrgHierarchy = {
  orgType: ORGANIZATION_TYPE.AWS,
  organization: { uid: "o-abc123def4", name: "My Org" },
  nodes: [
    {
      id: "ou-1",
      kind: NODE_KIND.ORGANIZATIONAL_UNIT,
      name: "OU One",
      parentId: "r-root",
    },
  ],
  candidates: [
    { uid: "111111111111", label: "App", parentId: "ou-1" },
    { uid: "222222222222", label: "Security", parentId: "ou-1" },
  ],
};

describe("useOrgSetupStore", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    useOrgSetupStore.getState().reset();
  });

  it("persists organization wizard state in sessionStorage", () => {
    // Given
    useOrgSetupStore
      .getState()
      .setOrganization("org-1", "My Org", "o-abc123def4");
    useOrgSetupStore.getState().setDiscovery("discovery-1", hierarchy);
    useOrgSetupStore
      .getState()
      .setSelectedCandidateIds(["111111111111", "222222222222"]);

    // When
    const persistedValue = sessionStorage.getItem("org-setup-store");

    // Then
    expect(persistedValue).toBeTruthy();
    expect(localStorage.getItem("org-setup-store")).toBeNull();
  });

  it.each([
    // Every `ORGANIZATION_TYPE` can be onboarded now, so the "no onboarding
    // flow" case has to come from outside the enum — which is where it really
    // comes from: this slot is rehydrated from untrusted sessionStorage.
    ["an organization type with no onboarding flow", "oraclecloud"],
    ["a prototype key", "__proto__"],
    ["a non-string", 42],
  ])("discards %s rehydrated as the organization type", (_label, stored) => {
    // Given — sessionStorage is untrusted and this slot is a discriminant. The
    // version comes from the store so a bump cannot make this pass vacuously.
    sessionStorage.setItem(
      "org-setup-store",
      JSON.stringify({
        state: {
          organizationType: stored,
          organizationId: "org-9",
          selectedCandidateIds: [],
        },
        version: useOrgSetupStore.persist.getOptions().version,
      }),
    );

    // When
    useOrgSetupStore.persist.rehydrate();

    // Then — the snapshot was read (so this is not passing by rehydration
    // silently not happening), but the bad discriminant did not survive it.
    expect(useOrgSetupStore.getState().organizationId).toBe("org-9");
    expect(useOrgSetupStore.getState().organizationType).toBe(
      ORGANIZATION_TYPE.AWS,
    );
  });

  it("keeps an onboardable organization type through rehydration", () => {
    // Given — the guard above must reject only what has no flow, not everything
    // that isn't AWS: a resumed Azure wizard has to come back as Azure.
    sessionStorage.setItem(
      "org-setup-store",
      JSON.stringify({
        state: {
          organizationType: ORGANIZATION_TYPE.AZURE,
          organizationId: "org-9",
          selectedCandidateIds: [],
        },
        version: useOrgSetupStore.persist.getOptions().version,
      }),
    );

    // When
    useOrgSetupStore.persist.rehydrate();

    // Then
    expect(useOrgSetupStore.getState().organizationType).toBe(
      ORGANIZATION_TYPE.AZURE,
    );
  });
});
