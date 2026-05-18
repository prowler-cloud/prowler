import { describe, expect, it } from "vitest";

import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

import {
  addCredentialsFormSchema,
  addCredentialsRoleFormSchema,
  addProviderFormSchema,
} from "./formSchemas";

const BASE_AWS_ROLE_VALUES = {
  [ProviderCredentialFields.PROVIDER_ID]: "provider-123",
  [ProviderCredentialFields.PROVIDER_TYPE]: "aws",
  [ProviderCredentialFields.ROLE_ARN]:
    "arn:aws:iam::123456789012:role/ProwlerRole",
  [ProviderCredentialFields.EXTERNAL_ID]: "tenant-123",
  [ProviderCredentialFields.CREDENTIALS_TYPE]: "access-secret-key",
} as const;

describe("addCredentialsRoleFormSchema", () => {
  it("accepts AWS role credentials when access and secret keys are present", () => {
    const schema = addCredentialsRoleFormSchema("aws");

    const result = schema.safeParse({
      ...BASE_AWS_ROLE_VALUES,
      [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "AKIA1234567890EXAMPLE",
      [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]:
        "test/secret+access=key1234567890",
    });

    expect(result.success).toBe(true);
  });

  it("reports missing AWS secret access key on aws_secret_access_key field", () => {
    const schema = addCredentialsRoleFormSchema("aws");

    const result = schema.safeParse({
      ...BASE_AWS_ROLE_VALUES,
      [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "AKIA1234567890EXAMPLE",
      [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: "",
    });

    expect(result.success).toBe(false);
    if (result.success) return;

    expect(result.error.issues).toContainEqual(
      expect.objectContaining({
        path: [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY],
      }),
    );
  });
});

describe("addProviderFormSchema - okta", () => {
  const validUidFixtures = [
    "acme.okta.com",
    "acme.oktapreview.com",
    "acme.okta-emea.com",
    "agency.okta-gov.com",
    "agency.okta.mil",
    "agency.okta-miltest.com",
    "agency.trex-govcloud.com",
  ];

  it.each(validUidFixtures)("accepts okta-managed org domain %s", (uid) => {
    const result = addProviderFormSchema.safeParse({
      providerType: "okta",
      providerUid: uid,
      providerAlias: "okta-test",
    });

    expect(result.success).toBe(true);
  });

  const invalidUidFixtures = [
    "https://acme.okta.com",
    "acme.example.com",
    "Acme.okta.com",
    "acme.okta.com/path",
    "",
  ];

  it.each(invalidUidFixtures)("rejects invalid okta org domain %s", (uid) => {
    const result = addProviderFormSchema.safeParse({
      providerType: "okta",
      providerUid: uid,
      providerAlias: "okta-test",
    });

    expect(result.success).toBe(false);
  });
});

describe("addCredentialsFormSchema - okta", () => {
  const BASE_OKTA_VALUES = {
    [ProviderCredentialFields.PROVIDER_ID]: "provider-okta-1",
    [ProviderCredentialFields.PROVIDER_TYPE]: "okta",
  } as const;

  it("accepts okta credentials when client id and private key are present", () => {
    const schema = addCredentialsFormSchema("okta");

    const result = schema.safeParse({
      ...BASE_OKTA_VALUES,
      [ProviderCredentialFields.OKTA_CLIENT_ID]: "0oa123456789abcdef",
      [ProviderCredentialFields.OKTA_PRIVATE_KEY]:
        "-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----",
    });

    expect(result.success).toBe(true);
  });

  it("reports missing okta private key on okta_private_key field", () => {
    const schema = addCredentialsFormSchema("okta");

    const result = schema.safeParse({
      ...BASE_OKTA_VALUES,
      [ProviderCredentialFields.OKTA_CLIENT_ID]: "0oa123456789abcdef",
      [ProviderCredentialFields.OKTA_PRIVATE_KEY]: "",
    });

    expect(result.success).toBe(false);
    if (result.success) return;

    expect(result.error.issues).toContainEqual(
      expect.objectContaining({
        path: [ProviderCredentialFields.OKTA_PRIVATE_KEY],
      }),
    );
  });
});
