import { beforeEach, describe, expect, it } from "vitest";

import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";

import { useProviderWizardStore } from "./store";

describe("useProviderWizardStore", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    useProviderWizardStore.getState().reset();
  });

  it("stores provider identity and mode, then resets to defaults", () => {
    useProviderWizardStore.getState().setProvider({
      id: "provider-1",
      type: "aws",
      uid: "123456789012",
      alias: "prod-account",
    });
    useProviderWizardStore.getState().setVia("role");
    useProviderWizardStore.getState().setSecretId("secret-1");
    useProviderWizardStore.getState().setMode(PROVIDER_WIZARD_MODE.UPDATE);

    const afterSet = useProviderWizardStore.getState();
    expect(afterSet.providerId).toBe("provider-1");
    expect(afterSet.providerType).toBe("aws");
    expect(afterSet.providerUid).toBe("123456789012");
    expect(afterSet.providerAlias).toBe("prod-account");
    expect(afterSet.via).toBe("role");
    expect(afterSet.secretId).toBe("secret-1");
    expect(afterSet.mode).toBe(PROVIDER_WIZARD_MODE.UPDATE);

    useProviderWizardStore.getState().reset();
    const afterReset = useProviderWizardStore.getState();

    expect(afterReset.providerId).toBeNull();
    expect(afterReset.providerType).toBeNull();
    expect(afterReset.providerUid).toBeNull();
    expect(afterReset.providerAlias).toBeNull();
    expect(afterReset.via).toBeNull();
    expect(afterReset.secretId).toBeNull();
    expect(afterReset.mode).toBe(PROVIDER_WIZARD_MODE.ADD);
  });

  it("persists provider wizard state in sessionStorage", () => {
    // Given
    useProviderWizardStore.getState().setProvider({
      id: "provider-1",
      type: "aws",
      uid: "123456789012",
      alias: "prod-account",
    });

    // When
    const persistedValue = sessionStorage.getItem("provider-wizard-store");

    // Then
    expect(persistedValue).toBeTruthy();
    expect(localStorage.getItem("provider-wizard-store")).toBeNull();
  });
});
