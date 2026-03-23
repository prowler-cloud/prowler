import { beforeEach, describe, expect, it } from "vitest";

import { useOrgSetupStore } from "./store";

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
    useOrgSetupStore.getState().setDiscovery("discovery-1", {
      roots: [],
      organizational_units: [],
      accounts: [],
    });
    useOrgSetupStore
      .getState()
      .setSelectedAccountIds(["111111111111", "222222222222"]);

    // When
    const persistedValue = sessionStorage.getItem("org-setup-store");

    // Then
    expect(persistedValue).toBeTruthy();
    expect(localStorage.getItem("org-setup-store")).toBeNull();
  });
});
