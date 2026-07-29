import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { PROVIDER_WIZARD_STEP } from "@/types/provider-wizard";

import {
  getAWSCredentialsTemplateLinks,
  getAWSOrgDeploymentQuickLink,
  getProviderHelpText,
  PROWLER_CF_TEMPLATE_URL,
} from "./external-urls";

function getQuickCreateParams(link: string): URLSearchParams {
  const hashQuery = new URL(link).hash.split("?")[1];
  return new URLSearchParams(hashQuery);
}

describe("getAWSCredentialsTemplateLinks", () => {
  it("should preserve dynamic values as single CloudFormation parameters", () => {
    // Given
    const externalId = "tenant&id";
    const bucketName = "bucket&param_DeployStackSet=false";

    // When
    const links = getAWSCredentialsTemplateLinks(
      externalId,
      bucketName,
      "amazon_s3",
      "123456789012",
    );
    const params = getQuickCreateParams(links.cloudformationQuickLink);

    // Then
    expect(params.get("param_ExternalId")).toBe(externalId);
    expect(params.get("param_S3IntegrationBucketName")).toBe(bucketName);
    expect(params.get("param_S3IntegrationBucketAccountId")).toBe(
      "123456789012",
    );
    expect(params.get("param_DeployStackSet")).toBeNull();
  });

  it("should omit S3 integration parameters when the bucket account id is missing", () => {
    // Given - the template requires S3IntegrationBucketAccountId whenever
    // EnableS3Integration is true, so an incomplete link would fail CFN
    // validation. This is reachable from the edit-credentials flow, where the
    // account id can resolve to an empty string.
    const externalId = "tenant-id";
    const bucketName = "my-findings-bucket";

    // When
    const links = getAWSCredentialsTemplateLinks(
      externalId,
      bucketName,
      "amazon_s3",
    );
    const params = getQuickCreateParams(links.cloudformationQuickLink);

    // Then
    expect(params.get("param_ExternalId")).toBe(externalId);
    expect(params.get("param_EnableS3Integration")).toBeNull();
    expect(params.get("param_S3IntegrationBucketName")).toBeNull();
    expect(params.get("param_S3IntegrationBucketAccountId")).toBeNull();
  });
});

describe("getAWSOrgDeploymentQuickLink", () => {
  it("should include the one-step organization deployment parameters", () => {
    // Given
    const externalId = "tenant&id";
    const organizationalUnitId = "ou-abcd-12345678";

    // When
    const link = getAWSOrgDeploymentQuickLink({
      externalId,
      organizationalUnitId,
      deployFromDelegatedAdmin: true,
    });
    const params = getQuickCreateParams(link);

    // Then
    expect(params.get("templateURL")).toBe(PROWLER_CF_TEMPLATE_URL);
    expect(params.get("param_ExternalId")).toBe(externalId);
    expect(params.get("param_AWSOrganizationalUnitId")).toBe(
      organizationalUnitId,
    );
    expect(params.get("param_EnableOrganizations")).toBe("true");
    expect(params.get("param_DeployLocalRole")).toBe("true");
    expect(params.get("param_DeployStackSet")).toBe("true");
    expect(params.get("param_DeployFromDelegatedAdmin")).toBe("true");
  });

  it("should omit delegated administrator mode for management accounts", () => {
    // Given
    const organizationalUnitId = "r-abcd";

    // When
    const link = getAWSOrgDeploymentQuickLink({
      externalId: "tenant-id",
      organizationalUnitId,
    });
    const params = getQuickCreateParams(link);

    // Then
    expect(params.get("param_AWSOrganizationalUnitId")).toBe(
      organizationalUnitId,
    );
    expect(params.get("param_DeployFromDelegatedAdmin")).toBeNull();
  });
});

describe("getProviderHelpText", () => {
  const AWS_SHORTLINK = "https://goto.prowler.com/provider-aws";
  const AWS_AUTH_DOCS =
    "https://docs.prowler.com/user-guide/providers/aws/authentication";

  it("returns the provider shortlink on the connect step", () => {
    // Given the user is picking a provider (no deep-link into auth yet)
    // When
    const { link } = getProviderHelpText("aws", PROVIDER_WIZARD_STEP.CONNECT);

    // Then
    expect(link).toBe(AWS_SHORTLINK);
  });

  it("points to the dedicated authentication docs page on the credentials step", () => {
    // Given the user is entering credentials
    // When
    const { link } = getProviderHelpText(
      "aws",
      PROVIDER_WIZARD_STEP.CREDENTIALS,
    );

    // Then
    expect(link).toBe(AWS_AUTH_DOCS);
  });

  it("keeps the shortlink on the test connection step", () => {
    // Auth docs are only surfaced while the user is still supplying
    // credentials; after that the shortlink landing is the useful destination.
    const { link } = getProviderHelpText("aws", PROVIDER_WIZARD_STEP.TEST);

    expect(link).toBe(AWS_SHORTLINK);
  });

  it("keeps the shortlink on the launch step", () => {
    const { link } = getProviderHelpText("aws", PROVIDER_WIZARD_STEP.LAUNCH);

    expect(link).toBe(AWS_SHORTLINK);
  });

  it("falls back to the shortlink + #authentication anchor when the provider has no dedicated auth page", () => {
    // Kubernetes documents authentication inline in getting-started-k8s.mdx
    // instead of a dedicated page, so on the credentials step we deep-link
    // via the getting-started shortlink to the {#authentication} anchor.
    const { link } = getProviderHelpText(
      "kubernetes",
      PROVIDER_WIZARD_STEP.CREDENTIALS,
    );

    expect(link).toBe("https://goto.prowler.com/provider-k8s#authentication");
  });

  it("resolves the credentials-step link for every supported provider", () => {
    // Guard against silently dropping a provider from either map. Providers
    // with a dedicated auth page resolve to that URL; Kubernetes falls back
    // to the shortlink + anchor.
    const cases: Array<[string, string]> = [
      [
        "aws",
        "https://docs.prowler.com/user-guide/providers/aws/authentication",
      ],
      [
        "azure",
        "https://docs.prowler.com/user-guide/providers/azure/authentication",
      ],
      [
        "m365",
        "https://docs.prowler.com/user-guide/providers/microsoft365/authentication",
      ],
      [
        "gcp",
        "https://docs.prowler.com/user-guide/providers/gcp/authentication",
      ],
      ["kubernetes", "https://goto.prowler.com/provider-k8s#authentication"],
      [
        "github",
        "https://docs.prowler.com/user-guide/providers/github/authentication",
      ],
      [
        "iac",
        "https://docs.prowler.com/user-guide/providers/iac/authentication",
      ],
      [
        "image",
        "https://docs.prowler.com/user-guide/providers/image/authentication",
      ],
      [
        "oraclecloud",
        "https://docs.prowler.com/user-guide/providers/oci/authentication",
      ],
      [
        "mongodbatlas",
        "https://docs.prowler.com/user-guide/providers/mongodbatlas/authentication",
      ],
      [
        "alibabacloud",
        "https://docs.prowler.com/user-guide/providers/alibabacloud/authentication",
      ],
      [
        "cloudflare",
        "https://docs.prowler.com/user-guide/providers/cloudflare/authentication",
      ],
      [
        "openstack",
        "https://docs.prowler.com/user-guide/providers/openstack/authentication",
      ],
      [
        "googleworkspace",
        "https://docs.prowler.com/user-guide/providers/googleworkspace/authentication",
      ],
      [
        "vercel",
        "https://docs.prowler.com/user-guide/providers/vercel/authentication",
      ],
      [
        "okta",
        "https://docs.prowler.com/user-guide/providers/okta/authentication",
      ],
    ];

    for (const [provider, expected] of cases) {
      expect(
        getProviderHelpText(provider, PROVIDER_WIZARD_STEP.CREDENTIALS).link,
      ).toBe(expected);
    }
  });

  it("falls back to the generic help shortlink for unknown providers regardless of step", () => {
    // Unknown providers have no dedicated docs page, so a step-specific
    // anchor would deep-link into nothing.
    const { link } = getProviderHelpText(
      "not-a-real-provider",
      PROVIDER_WIZARD_STEP.CREDENTIALS,
    );

    expect(link).toBe("https://goto.prowler.com/provider-help");
  });
});

describe("Prowler CloudFormation template", () => {
  it("should define every parameter used by the UI quick-create links", () => {
    // Given
    const template = readFileSync(
      join(
        process.cwd(),
        "..",
        "permissions/templates/cloudformation/prowler-scan-role.yml",
      ),
      "utf8",
    );

    // Then
    expect(template).toContain("  EnableOrganizations:");
    expect(template).toContain("  S3IntegrationBucketAccountId:");
    expect(template).toContain("  DeployStackSet:");
    expect(template).toContain("  DeployLocalRole:");
    expect(template).toContain("  AWSOrganizationalUnitId:");
    expect(template).toContain("  DeployFromDelegatedAdmin:");
  });
});
