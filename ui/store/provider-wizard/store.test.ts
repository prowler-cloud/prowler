import { describe, expect, it } from "vitest";

import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";

import { useProviderWizardStore } from "./store";

describe("useProviderWizardStore", () => {
  it("stores provider identity and mode, then resets to defaults", () => {
    useProviderWizardStore.getState().reset();

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
});
