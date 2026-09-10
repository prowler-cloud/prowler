import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { PROVIDER_WIZARD_STEP } from "@/types/provider-wizard";

import {
  buildCloudflareAccountOwnedApiTokenUrl,
  buildGitHubPersonalAccessTokenOrgUrl,
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
  it("keeps the Cloudflare User API Token URL under the profile route with the four required read scopes", () => {
    // Snapshot check: fixes the exact URL so a stray edit to the permission
    // scopes, token name, account/zone selectors or console origin trips a
    // failing test instead of silently shipping a broken pre-configured
    // token flow to users. Matches the "User API Token" link in
    // docs/user-guide/providers/cloudflare/authentication.mdx.
    expect(PRECONFIGURED_CREDENTIAL_URLS.CLOUDFLARE_API_TOKEN_USER).toBe(
      "https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22zone_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22dns%22%2C%22type%22%3A%22read%22%7D%5D&accountId=%2A&zoneId=all&name=Prowler%20Security%20Scanner",
    );
  });

  it("carries the four Prowler read scopes as decoded permissionGroupKeys on the Cloudflare User API Token URL", () => {
    // Semantic contract: the URL must request read on account_settings, zone,
    // zone_settings and dns and reuse the shared Prowler token name.
    const parsed = new URL(
      PRECONFIGURED_CREDENTIAL_URLS.CLOUDFLARE_API_TOKEN_USER,
    );
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
  });

  it("keeps the GitHub user-scope PAT URL pre-filled with the four required read permissions", () => {
    // Snapshot check: fixes the exact URL so any accidental scope broadening
    // (or a rename of `expires_in` / permission slugs on GitHub's side) trips
    // a failing test. Matches the "user repositories" URL published in
    // docs/user-guide/providers/github/authentication.mdx.
    expect(
      PRECONFIGURED_CREDENTIAL_URLS.GITHUB_PERSONAL_ACCESS_TOKEN_USER,
    ).toBe(
      "https://github.com/settings/personal-access-tokens/new?name=Prowler+Security+Scanner&description=Fine-grained+PAT+for+Prowler+security+scanning&expires_in=90&administration=read&contents=read&vulnerability_alerts=read&emails=read",
    );
  });

  it("carries only read-level permissions on the GitHub user-scope PAT URL and no organization-only scopes", () => {
    // Semantic contract: every permission query-param must be `read`, and the
    // two organization-only permissions must NOT leak into the user URL
    // (otherwise GitHub would reject the whole permission set with a
    // Resource-Owner mismatch when the caller is a personal account).
    const parsed = new URL(
      PRECONFIGURED_CREDENTIAL_URLS.GITHUB_PERSONAL_ACCESS_TOKEN_USER,
    );

    expect(parsed.searchParams.get("name")).toBe("Prowler Security Scanner");
    expect(parsed.searchParams.get("expires_in")).toBe("90");
    expect(parsed.searchParams.get("organization_administration")).toBeNull();
    expect(parsed.searchParams.get("members")).toBeNull();

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

describe("buildCloudflareAccountOwnedApiTokenUrl", () => {
  it("pins the token to the account by routing through the dashboard `to=` param with the account id substituted", () => {
    // Cloudflare's SPA only reads the pre-fill query params
    // (`permissionGroupKeys`, `name`) when the user arrives via the dashboard
    // router with a `to=` value — navigating straight to
    // `/<accountId>/api-tokens/create?params` renders the form but drops the
    // params on the floor. Substituting the account id in place of the docs'
    // `:account` placeholder keeps the pre-fill working and avoids ambiguity
    // for users signed into multiple accounts.
    const url = new URL(
      buildCloudflareAccountOwnedApiTokenUrl(
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
      ),
    );

    expect(url.origin).toBe("https://dash.cloudflare.com");
    expect(url.pathname).toBe("/");
    expect(url.searchParams.get("to")).toBe(
      "/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4/api-tokens",
    );
    expect(url.searchParams.get("name")).toBe("Prowler Security Scanner");
    const permissionGroupKeys = JSON.parse(
      url.searchParams.get("permissionGroupKeys") ?? "[]",
    );
    expect(permissionGroupKeys).toEqual([
      { key: "account_settings", type: "read" },
      { key: "zone", type: "read" },
      { key: "zone_settings", type: "read" },
      { key: "dns", type: "read" },
    ]);
  });

  it("keeps the `to=` path unencoded so Cloudflare's router matches it", () => {
    // Cloudflare's router matches on the raw string in `to`, so the slashes
    // inside `/<accountId>/api-tokens` must NOT be percent-encoded.
    // URLSearchParams would encode them; asserting the raw substring guards
    // against a future refactor that swaps the manual query-string build for
    // URLSearchParams.
    const url = buildCloudflareAccountOwnedApiTokenUrl(
      "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    );

    expect(url).toContain("?to=/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4/api-tokens&");
  });

  it("URL-encodes account ids that contain characters requiring escaping", () => {
    // Real Cloudflare account ids are hex strings today, but the wizard
    // accepts whatever the user typed. Encoding the account id inside the
    // `to=` path prevents a stray `/` or `#` from silently breaking the URL:
    // an unencoded `#` would truncate the query string, and an unencoded `/`
    // would let Cloudflare mis-parse the account id boundary.
    const url = buildCloudflareAccountOwnedApiTokenUrl("acct/with#gaps");

    expect(url).toContain("?to=/acct%2Fwith%23gaps/api-tokens&");
  });
});

describe("buildGitHubPersonalAccessTokenOrgUrl", () => {
  it("pins the token Resource Owner via target_name and requests the org-only permissions", () => {
    // Without a `target_name`, GitHub silently ignores the two organization
    // permissions (`organization_administration`, `members`) because the
    // Resource Owner defaults to the caller's personal account. Pinning the
    // owner is what makes the pre-checked org permissions actually surface.
    const url = new URL(buildGitHubPersonalAccessTokenOrgUrl("prowler-cloud"));

    expect(url.origin + url.pathname).toBe(
      "https://github.com/settings/personal-access-tokens/new",
    );
    expect(url.searchParams.get("target_name")).toBe("prowler-cloud");
    expect(url.searchParams.get("organization_administration")).toBe("read");
    expect(url.searchParams.get("members")).toBe("read");
    expect(url.searchParams.get("administration")).toBe("read");
    expect(url.searchParams.get("contents")).toBe("read");
    expect(url.searchParams.get("vulnerability_alerts")).toBe("read");
    expect(url.searchParams.get("name")).toBe("Prowler Security Scanner");
    expect(url.searchParams.get("expires_in")).toBe("90");
  });

  it("omits the account-only `emails` permission from the org URL", () => {
    // `emails` is an account-level permission that only makes sense when the
    // Resource Owner is a personal user account. Including it on an org URL
    // would cause GitHub to reject the whole permission set.
    const url = new URL(buildGitHubPersonalAccessTokenOrgUrl("prowler-cloud"));

    expect(url.searchParams.get("emails")).toBeNull();
  });

  it("URL-encodes an organization slug that contains characters requiring escaping", () => {
    // GitHub org slugs cannot contain `&` or spaces today, but callers pass
    // whatever the wizard collected verbatim, so the helper must not blindly
    // concatenate. URLSearchParams enforces percent-encoding.
    const url = new URL(
      buildGitHubPersonalAccessTokenOrgUrl("prowler & friends"),
    );

    expect(url.searchParams.get("target_name")).toBe("prowler & friends");
    expect(url.search).toContain("target_name=prowler+%26+friends");
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
