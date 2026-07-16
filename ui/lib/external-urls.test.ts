import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  getAWSCredentialsTemplateLinks,
  getAWSOrgDeploymentQuickLink,
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
    expect(params.get("param_DeployStackSet")).toBeNull();
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
