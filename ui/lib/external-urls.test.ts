import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { PROVIDER_WIZARD_STEP } from "@/types/provider-wizard";

import {
  getAWSCredentialsTemplateLinks,
  getAWSOrgDeploymentQuickLink,
  PRECONFIGURED_CREDENTIAL_URLS,
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

  it("keeps the GitHub fine-grained PAT URL pointing at the new-token form pre-filled with every required read permission", () => {
    // Snapshot check: fixes the exact URL so any accidental scope broadening
    // (or a rename of `expires_in` / permission slugs on GitHub's side) trips
    // a failing test. The URL is the superset of the personal and org
    // templates published in docs/user-guide/providers/github/authentication.mdx:
    // `organization_administration` and `members` only surface in GitHub's UI
    // when the token Resource Owner is set to an organization (silently
    // ignored for personal accounts), so a single link serves both flows.
    expect(PRECONFIGURED_CREDENTIAL_URLS.GITHUB_PERSONAL_ACCESS_TOKEN).toBe(
      "https://github.com/settings/personal-access-tokens/new?name=Prowler+Security+Scanner&description=Fine-grained+PAT+for+Prowler+security+scanning&expires_in=90&administration=read&contents=read&vulnerability_alerts=read&emails=read&organization_administration=read&members=read",
    );
  });

  it("carries only read-level permissions and the Prowler token name/expiry on the GitHub PAT URL", () => {
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

  it("includes the two organization-only permissions so organization scans work when the Resource Owner is switched", () => {
    // The two params `organization_administration` and `members` are hidden in
    // GitHub's UI for personal accounts but appear pre-checked once the user
    // switches the token Resource Owner to their organization. Without them
    // Prowler cannot run organization-level checks (MFA policy, member audit,
    // etc.). Matches the org-scope URL published in
    // docs/user-guide/providers/github/authentication.mdx.
    const parsed = new URL(
      PRECONFIGURED_CREDENTIAL_URLS.GITHUB_PERSONAL_ACCESS_TOKEN,
    );

    expect(parsed.searchParams.get("organization_administration")).toBe("read");
    expect(parsed.searchParams.get("members")).toBe("read");
  });
});

describe("getProviderHelpText", () => {
  const AWS_SHORTLINK = "https://goto.prowler.com/provider-aws";
  const AWS_CREDENTIALS_STEP_DOCS =
    "https://docs.prowler.com/user-guide/providers/aws/getting-started-aws#step-3-set-up-aws-authentication";

  it("returns the provider shortlink on the connect step", () => {
    // Given the user is picking a provider (no deep-link into auth yet)
    // When
    const { link } = getProviderHelpText("aws", PROVIDER_WIZARD_STEP.CONNECT);

    // Then
    expect(link).toBe(AWS_SHORTLINK);
  });

  it("points to the credentials section of the getting-started page on the credentials step", () => {
    // No method picked yet — link should scroll the getting-started page to
    // the credentials/authentication step so the user reads about the choice
    // in the same page they came from.
    const { link } = getProviderHelpText(
      "aws",
      PROVIDER_WIZARD_STEP.CREDENTIALS,
    );

    expect(link).toBe(AWS_CREDENTIALS_STEP_DOCS);
  });

  it("points AWS assume role credentials to the exact setup section", () => {
    const { link } = getProviderHelpText(
      "aws",
      PROVIDER_WIZARD_STEP.CREDENTIALS,
      "role",
    );

    expect(link).toBe(
      "https://docs.prowler.com/user-guide/providers/aws/getting-started-aws#assume-role-recommended",
    );
  });

  it("points AWS static credentials to the exact setup section", () => {
    const { link } = getProviderHelpText(
      "aws",
      PROVIDER_WIZARD_STEP.CREDENTIALS,
      "credentials",
    );

    expect(link).toBe(
      "https://docs.prowler.com/user-guide/providers/aws/getting-started-aws#credentials-static-access-keys",
    );
  });

  it("falls back to the credentials step section when the picked method has no dedicated subsection", () => {
    // GCP's methods render inside a Mintlify <Tabs> component in the docs
    // page, so no per-method anchor exists. Any method-selected variant
    // resolves to the general credentials step anchor.
    const { link } = getProviderHelpText(
      "gcp",
      PROVIDER_WIZARD_STEP.CREDENTIALS,
      "service-account",
    );

    expect(link).toBe(
      "https://docs.prowler.com/user-guide/providers/gcp/getting-started-gcp#step-3-set-up-gcp-authentication",
    );
  });

  it("keeps the shortlink on the test connection step", () => {
    // Credentials-step docs are only surfaced while the user is still
    // supplying credentials; after that the shortlink landing is the useful
    // destination.
    const { link } = getProviderHelpText("aws", PROVIDER_WIZARD_STEP.TEST);

    expect(link).toBe(AWS_SHORTLINK);
  });

  it("keeps the shortlink on the launch step", () => {
    const { link } = getProviderHelpText("aws", PROVIDER_WIZARD_STEP.LAUNCH);

    expect(link).toBe(AWS_SHORTLINK);
  });

  it("resolves the credentials-step link for every supported provider", () => {
    // Guard against silently dropping a provider from
    // PROVIDER_CREDENTIALS_STEP_DOCS_URL. When no auth method is selected
    // yet, every provider should deep-link to its own getting-started
    // credentials section (never to authentication.mdx).
    const cases: Array<[string, string]> = [
      [
        "aws",
        "https://docs.prowler.com/user-guide/providers/aws/getting-started-aws#step-3-set-up-aws-authentication",
      ],
      [
        "azure",
        "https://docs.prowler.com/user-guide/providers/azure/getting-started-azure#step-3-add-credentials-to-prowler-cloud",
      ],
      [
        "m365",
        "https://docs.prowler.com/user-guide/providers/microsoft365/getting-started-m365#step-3-choose-and-provide-authentication",
      ],
      [
        "gcp",
        "https://docs.prowler.com/user-guide/providers/gcp/getting-started-gcp#step-3-set-up-gcp-authentication",
      ],
      [
        "kubernetes",
        "https://docs.prowler.com/user-guide/providers/kubernetes/getting-started-k8s#step-2-configure-kubernetes-authentication",
      ],
      [
        "github",
        "https://docs.prowler.com/user-guide/providers/github/getting-started-github#step-3-choose-authentication-method",
      ],
      [
        "iac",
        "https://docs.prowler.com/user-guide/providers/iac/getting-started-iac#step-2-enter-authentication-details",
      ],
      [
        "image",
        "https://docs.prowler.com/user-guide/providers/image/getting-started-image#step-2-enter-authentication-and-scan-filters",
      ],
      [
        "oraclecloud",
        "https://docs.prowler.com/user-guide/providers/oci/getting-started-oci#step-3-add-oci-api-key-credentials",
      ],
      [
        "mongodbatlas",
        "https://docs.prowler.com/user-guide/providers/mongodbatlas/getting-started-mongodbatlas#step-2-provide-api-credentials",
      ],
      [
        "alibabacloud",
        "https://docs.prowler.com/user-guide/providers/alibabacloud/getting-started-alibabacloud#step-3-choose-and-provide-authentication",
      ],
      [
        "cloudflare",
        "https://docs.prowler.com/user-guide/providers/cloudflare/getting-started-cloudflare#step-3-choose-and-provide-authentication",
      ],
      [
        "openstack",
        "https://docs.prowler.com/user-guide/providers/openstack/getting-started-openstack#step-2-provide-credentials",
      ],
      [
        "googleworkspace",
        "https://docs.prowler.com/user-guide/providers/googleworkspace/getting-started-googleworkspace#step-3-provide-credentials",
      ],
      [
        "vercel",
        "https://docs.prowler.com/user-guide/providers/vercel/getting-started-vercel#step-2-provide-credentials",
      ],
      [
        "okta",
        "https://docs.prowler.com/user-guide/providers/okta/getting-started-okta#step-2-provide-credentials",
      ],
    ];

    for (const [provider, expected] of cases) {
      expect(
        getProviderHelpText(provider, PROVIDER_WIZARD_STEP.CREDENTIALS).link,
      ).toBe(expected);
    }
  });

  it("resolves the method-specific credentials link for every provider with a per-method subsection", () => {
    // Providers whose docs have a heading per auth method: verify each
    // (provider, method) combo maps to the exact subsection anchor. Missing
    // an entry in PROVIDER_CREDENTIALS_METHOD_DOCS_URL silently regresses
    // the user to the general step section — this test catches that.
    const cases: Array<[string, string, string]> = [
      [
        "aws",
        "role",
        "https://docs.prowler.com/user-guide/providers/aws/getting-started-aws#assume-role-recommended",
      ],
      [
        "aws",
        "credentials",
        "https://docs.prowler.com/user-guide/providers/aws/getting-started-aws#credentials-static-access-keys",
      ],
      [
        "m365",
        "app_certificate",
        "https://docs.prowler.com/user-guide/providers/microsoft365/getting-started-m365#application-certificate-authentication-recommended",
      ],
      [
        "m365",
        "app_client_secret",
        "https://docs.prowler.com/user-guide/providers/microsoft365/getting-started-m365#application-client-secret-authentication",
      ],
      [
        "alibabacloud",
        "role",
        "https://docs.prowler.com/user-guide/providers/alibabacloud/getting-started-alibabacloud#ram-role-assumption-recommended",
      ],
      [
        "alibabacloud",
        "credentials",
        "https://docs.prowler.com/user-guide/providers/alibabacloud/getting-started-alibabacloud#credentials-static-access-keys",
      ],
      [
        "cloudflare",
        "api_token",
        "https://docs.prowler.com/user-guide/providers/cloudflare/getting-started-cloudflare#user-api-token-authentication-recommended",
      ],
      [
        "cloudflare",
        "api_key",
        "https://docs.prowler.com/user-guide/providers/cloudflare/getting-started-cloudflare#api-key-and-email-authentication-legacy",
      ],
    ];

    for (const [provider, method, expected] of cases) {
      expect(
        getProviderHelpText(provider, PROVIDER_WIZARD_STEP.CREDENTIALS, method)
          .link,
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

  it("falls back for unknown providers colliding with Object.prototype", () => {
    // Given
    const providers = ["constructor", "toString", "__proto__"];

    for (const provider of providers) {
      // When
      const { link } = getProviderHelpText(
        provider,
        PROVIDER_WIZARD_STEP.CREDENTIALS,
      );

      // Then
      expect(link).toBe("https://goto.prowler.com/provider-help");
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
