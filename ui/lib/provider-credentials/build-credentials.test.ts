import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib", () => ({
  filterEmptyValues: (obj: Record<string, unknown>) =>
    Object.fromEntries(
      Object.entries(obj).filter(([, value]) => {
        if (value === 0 || value === false) return true;
        if (value === null || value === undefined) return false;
        if (typeof value === "string" && value.trim() === "") return false;
        if (Array.isArray(value) && value.length === 0) return false;

        return true;
      }),
    ),
  getFormValue: (formData: FormData, field: string) => formData.get(field),
}));

import { buildOracleCloudSecret } from "./build-credentials";
import { ProviderCredentialFields } from "./provider-credential-fields";

describe("buildOracleCloudSecret", () => {
  it("emits canonical regions array from comma-separated input", () => {
    const formData = new FormData();
    formData.set(ProviderCredentialFields.OCI_USER, "ocid1.user.oc1..example");
    formData.set(ProviderCredentialFields.OCI_FINGERPRINT, "fingerprint");
    formData.set(ProviderCredentialFields.OCI_KEY_CONTENT, "private-key");
    formData.set(
      ProviderCredentialFields.OCI_REGION,
      " us-phoenix-1, us-ashburn-1 ",
    );

    const secret = buildOracleCloudSecret(
      formData,
      "ocid1.tenancy.oc1..example",
    );

    expect(secret).toMatchObject({
      user: "ocid1.user.oc1..example",
      fingerprint: "fingerprint",
      tenancy: "ocid1.tenancy.oc1..example",
      regions: ["us-phoenix-1", "us-ashburn-1"],
    });
    expect(secret).not.toHaveProperty("region");
  });

  it("filters blank entries from comma-separated regions", () => {
    const formData = new FormData();
    formData.set(
      ProviderCredentialFields.OCI_REGION,
      "us-phoenix-1, , us-ashburn-1,",
    );

    const secret = buildOracleCloudSecret(
      formData,
      "ocid1.tenancy.oc1..example",
    );

    expect(secret).toMatchObject({
      regions: ["us-phoenix-1", "us-ashburn-1"],
    });
  });
});
