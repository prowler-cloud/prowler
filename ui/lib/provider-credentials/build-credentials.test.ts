import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib", () => ({
  getFormValue: (formData: FormData, field: string) => formData.get(field),
  filterEmptyValues: (obj: Record<string, unknown>) =>
    Object.fromEntries(
      Object.entries(obj).filter(([, value]) => {
        if (value === null || value === undefined) return false;
        if (typeof value === "string" && value.trim() === "") return false;
        return true;
      }),
    ),
}));

import { buildOracleCloudSecret } from "./build-credentials";
import { ProviderCredentialFields } from "./provider-credential-fields";

describe("buildOracleCloudSecret", () => {
  it("builds OCI API key credentials without region", () => {
    const formData = new FormData();
    const keyContent =
      "-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----";

    formData.set(ProviderCredentialFields.OCI_USER, "ocid1.user.oc1..example");
    formData.set(ProviderCredentialFields.OCI_FINGERPRINT, "aa:bb:cc:dd");
    formData.set(ProviderCredentialFields.OCI_KEY_CONTENT, keyContent);
    formData.set(
      ProviderCredentialFields.OCI_TENANCY,
      "ocid1.tenancy.oc1..example",
    );

    const secret = buildOracleCloudSecret(formData);

    expect(secret).toEqual({
      [ProviderCredentialFields.OCI_USER]: "ocid1.user.oc1..example",
      [ProviderCredentialFields.OCI_FINGERPRINT]: "aa:bb:cc:dd",
      [ProviderCredentialFields.OCI_KEY_CONTENT]: btoa(keyContent),
      [ProviderCredentialFields.OCI_TENANCY]: "ocid1.tenancy.oc1..example",
    });
    expect(secret).not.toHaveProperty(ProviderCredentialFields.OCI_REGION);
    expect(secret).not.toHaveProperty("regions");
  });
});
