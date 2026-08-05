import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  getAWSCredentialsTemplateLinks,
  getAWSOrgDeploymentQuickLink,
  PRECONFIGURED_CREDENTIAL_URLS,
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

describe("PRECONFIGURED_CREDENTIAL_URLS", () => {
  it("keeps the Cloudflare API Token URL pointing at the create-custom-token form with the four required read scopes", () => {
    // Snapshot check: fixes the exact URL so a stray edit to the permission
    // scopes, token name, account/zone selectors or console origin trips a
    // failing test instead of silently shipping a broken pre-configured
    // token flow to users.
    expect(PRECONFIGURED_CREDENTIAL_URLS.CLOUDFLARE_API_TOKEN).toBe(
      "https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22zone_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22dns%22%2C%22type%22%3A%22read%22%7D%5D&accountId=%2A&zoneId=all&name=Prowler%20Security%20Scanner",
    );
  });

  it("carries the four Prowler read scopes as decoded permissionGroupKeys", () => {
    // Beyond the raw snapshot, assert the semantic contract: the URL must
    // request read on account_settings, zone, zone_settings and dns.
    const parsed = new URL(PRECONFIGURED_CREDENTIAL_URLS.CLOUDFLARE_API_TOKEN);
    const permissionGroupKeys = JSON.parse(
      parsed.searchParams.get("permissionGroupKeys") ?? "[]",
    );

    expect(permissionGroupKeys).toEqual([
      { key: "account_settings", type: "read" },
      { key: "zone", type: "read" },
      { key: "zone_settings", type: "read" },
      { key: "dns", type: "read" },
    ]);
    expect(parsed.searchParams.get("name")).toBe("Prowler Security Scanner");
    expect(parsed.searchParams.get("accountId")).toBe("*");
    expect(parsed.searchParams.get("zoneId")).toBe("all");
  });

  it("keeps the GitHub fine-grained PAT URL pointing at the new-token form with the four required read permissions", () => {
    // Snapshot check: fixes the exact URL so any accidental scope broadening
    // (or a rename of `expires_in` / permission slugs on GitHub's side) trips
    // a failing test.
    expect(PRECONFIGURED_CREDENTIAL_URLS.GITHUB_PERSONAL_ACCESS_TOKEN).toBe(
      "https://github.com/settings/personal-access-tokens/new?name=Prowler+Security+Scanner&description=Fine-grained+PAT+for+Prowler+security+scanning&expires_in=90&administration=read&contents=read&vulnerability_alerts=read&emails=read",
    );
  });

  it("carries only read-level permissions and the Prowler token name/expiry", () => {
    // Semantic contract: every permission query-param must be `read`, the
    // token must expire in 90 days, and the name must match what the
    // Cloudflare token uses to keep the "Prowler" audit trail consistent.
    const parsed = new URL(
      PRECONFIGURED_CREDENTIAL_URLS.GITHUB_PERSONAL_ACCESS_TOKEN,
    );

    expect(parsed.searchParams.get("name")).toBe("Prowler Security Scanner");
    expect(parsed.searchParams.get("expires_in")).toBe("90");

    const NON_PERMISSION_PARAMS = new Set([
      "name",
      "description",
      "expires_in",
    ]);
    for (const [key, value] of Array.from(parsed.searchParams.entries())) {
      if (NON_PERMISSION_PARAMS.has(key)) continue;
      expect(
        value,
        `permission "${key}" should be granted at "read" level`,
      ).toBe("read");
    }
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
