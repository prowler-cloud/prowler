import { describe, expect, it } from "vitest";

import { DOCS_URLS, getProviderHelpText } from "@/lib/external-urls";
import { ORG_SETUP_PHASE, ORG_WIZARD_STEP } from "@/types/organizations";
import {
  PROVIDER_WIZARD_MODE,
  PROVIDER_WIZARD_STEP,
} from "@/types/provider-wizard";
import { type KnownProviderType, PROVIDER_TYPES } from "@/types/providers";

import {
  getOrganizationsStepperOffset,
  getProviderWizardDocsDestination,
  getProviderWizardModalTitle,
} from "./provider-wizard-modal.utils";

describe("getOrganizationsStepperOffset", () => {
  it("keeps step 1 active during organization details", () => {
    const offset = getOrganizationsStepperOffset(
      ORG_WIZARD_STEP.SETUP,
      ORG_SETUP_PHASE.DETAILS,
    );

    expect(offset).toBe(0);
  });

  it("moves to step 2 during credentials phase", () => {
    const offset = getOrganizationsStepperOffset(
      ORG_WIZARD_STEP.SETUP,
      ORG_SETUP_PHASE.ACCESS,
    );

    expect(offset).toBe(1);
  });

  it("uses step 2+ offset for later wizard steps", () => {
    const offset = getOrganizationsStepperOffset(
      ORG_WIZARD_STEP.VALIDATE,
      ORG_SETUP_PHASE.DETAILS,
    );

    expect(offset).toBe(1);
  });
});

describe("getProviderWizardModalTitle", () => {
  it("returns add title for add mode", () => {
    const title = getProviderWizardModalTitle(PROVIDER_WIZARD_MODE.ADD);

    expect(title).toBe("Adding A Provider");
  });

  it("returns update title for update mode", () => {
    const title = getProviderWizardModalTitle(PROVIDER_WIZARD_MODE.UPDATE);

    expect(title).toBe("Update Provider Credentials");
  });
});

describe("getProviderWizardDocsDestination", () => {
  it("returns a compact provider label for short provider docs links", () => {
    const destination = getProviderWizardDocsDestination(
      "https://goto.prowler.com/provider-aws",
    );

    expect(destination).toBe("AWS");
  });

  it("returns a compact provider label for deep-linked getting-started URLs", () => {
    const destination = getProviderWizardDocsDestination(
      "https://docs.prowler.com/user-guide/providers/aws/getting-started-aws",
    );

    expect(destination).toBe("AWS");
  });

  it("returns a specific label for AWS assume role docs links", () => {
    const destination = getProviderWizardDocsDestination(
      "https://docs.prowler.com/user-guide/providers/aws/getting-started-aws#assume-role-recommended",
    );

    expect(destination).toBe("AWS Assume Role");
  });

  it("returns a method-specific label for every subsection deep-link", () => {
    // Locks the docsSectionLabelMap keys to the URLs the frontend emits.
    // Adding a new (provider, method) subsection URL requires wiring a
    // matching label here or the modal header regresses to just the provider
    // name.
    const cases: Array<[string, string]> = [
      [
        "https://docs.prowler.com/user-guide/providers/aws/getting-started-aws#assume-role-recommended",
        "AWS Assume Role",
      ],
      [
        "https://docs.prowler.com/user-guide/providers/aws/getting-started-aws#credentials-static-access-keys",
        "AWS Credentials",
      ],
      [
        "https://docs.prowler.com/user-guide/providers/microsoft365/getting-started-m365#application-certificate-authentication-recommended",
        "M365 Certificate",
      ],
      [
        "https://docs.prowler.com/user-guide/providers/microsoft365/getting-started-m365#application-client-secret-authentication",
        "M365 Client Secret",
      ],
      [
        "https://docs.prowler.com/user-guide/providers/alibabacloud/getting-started-alibabacloud#ram-role-assumption-recommended",
        "Alibaba Cloud RAM Role",
      ],
      [
        "https://docs.prowler.com/user-guide/providers/alibabacloud/getting-started-alibabacloud#credentials-static-access-keys",
        "Alibaba Cloud Credentials",
      ],
      [
        "https://docs.prowler.com/user-guide/providers/cloudflare/getting-started-cloudflare#user-api-token-authentication-recommended",
        "Cloudflare API Token",
      ],
      [
        "https://docs.prowler.com/user-guide/providers/cloudflare/getting-started-cloudflare#api-key-and-email-authentication-legacy",
        "Cloudflare API Key",
      ],
    ];

    for (const [url, expected] of cases) {
      expect(getProviderWizardDocsDestination(url)).toBe(expected);
    }
  });

  it("ignores a #authentication anchor when deriving the label", () => {
    // The credentials step falls back to a shortlink + anchor for providers
    // without a dedicated auth page (Kubernetes). The label shown in the
    // modal header must stay the provider name, not shift with the anchor.
    const destination = getProviderWizardDocsDestination(
      "https://goto.prowler.com/provider-k8s#authentication",
    );

    expect(destination).toBe("Kubernetes");
  });

  it("derives the provider label from the dedicated authentication docs URL", () => {
    // On the credentials step providers with a standalone authentication.mdx
    // (all except Kubernetes) point to `/providers/<slug>/authentication`.
    // The label must come from the `<slug>` segment, not from the trailing
    // "authentication" page name.
    const destination = getProviderWizardDocsDestination(
      "https://docs.prowler.com/user-guide/providers/aws/authentication",
    );

    expect(destination).toBe("AWS");
  });

  it("maps the OCI docs slug to the Oracle Cloud label", () => {
    // The provider is called `oraclecloud` in the wizard but the docs path
    // uses the `oci` slug, so the parser must know both refer to the same
    // provider.
    const destination = getProviderWizardDocsDestination(
      "https://docs.prowler.com/user-guide/providers/oci/authentication",
    );

    expect(destination).toBe("Oracle Cloud");
  });

  it("maps the microsoft365 docs slug to the Microsoft 365 label", () => {
    // Same shape: the wizard's `m365` maps to the `microsoft365` folder in
    // docs, so the parser must recognise the folder slug as the provider.
    const destination = getProviderWizardDocsDestination(
      "https://docs.prowler.com/user-guide/providers/microsoft365/authentication",
    );

    expect(destination).toBe("Microsoft 365");
  });

  it("labels the Azure organizations tutorial after the wizard flow, not its page name", () => {
    // The Azure tutorial page is named after Management Groups while the wizard
    // flow is "Azure Organizations", so the label cannot be derived from the
    // slug — without the map entry the header would read "Azure Management
    // Groups Documentation".
    const destination = getProviderWizardDocsDestination(
      DOCS_URLS.AZURE_ORGANIZATIONS,
    );

    expect(destination).toBe("Azure Organizations");
  });

  it("returns a compact destination label for long docs links", () => {
    const destination = getProviderWizardDocsDestination(
      "https://docs.prowler.com/user-guide/tutorials/prowler-cloud-aws-organizations",
    );

    expect(destination).toBe("AWS Organizations");
  });
});

// The URL maps in `ui/lib/external-urls.ts` and the `destinationLabelMap` in
// this file share the same set of providers but use different keys (wizard
// slug vs. docs path slug — e.g. `oraclecloud` vs `oci`, `m365` vs
// `microsoft365`). Nothing structural stops a provider from being added to
// one file and forgotten in the other, which would silently render the
// title-cased URL segment (e.g. "Getting Started Aws") in the modal header
// instead of the intended label.
//
// This suite locks the end-to-end contract: for every provider in
// `PROVIDER_TYPES`, on every wizard step, the URL emitted by
// `getProviderHelpText` must round-trip through the parser into the expected
// label. `Record<KnownProviderType, ...>` also gives compile-time coverage —
// adding a provider to `PROVIDER_TYPES` requires updating this table.
const EXPECTED_MODAL_HEADER_LABEL: Record<KnownProviderType, string> = {
  aws: "AWS",
  azure: "Azure",
  m365: "Microsoft 365",
  gcp: "GCP",
  kubernetes: "Kubernetes",
  github: "GitHub",
  iac: "IaC",
  image: "Image",
  oraclecloud: "Oracle Cloud",
  mongodbatlas: "MongoDB Atlas",
  alibabacloud: "Alibaba Cloud",
  cloudflare: "Cloudflare",
  openstack: "OpenStack",
  googleworkspace: "Google Workspace",
  vercel: "Vercel",
  okta: "Okta",
};

// Method-specific labels for the credentials step. Providers with per-method
// docs subsections (AWS, M365, Alibaba Cloud, Cloudflare) must round-trip
// through `getProviderWizardDocsDestination` into a specific label —
// otherwise the URL in `PROVIDER_CREDENTIALS_METHOD_DOCS_URL` and the label
// in `docsSectionLabelMap` have drifted apart. Providers without a per-method
// deep link (GCP, GitHub, and every single-method provider) fall through to
// the generic `EXPECTED_MODAL_HEADER_LABEL` above and are not listed here.
const EXPECTED_METHOD_MODAL_HEADER_LABEL: Array<
  [KnownProviderType, string, string]
> = [
  ["aws", "role", "AWS Assume Role"],
  ["aws", "credentials", "AWS Credentials"],
  ["m365", "app_certificate", "M365 Certificate"],
  ["m365", "app_client_secret", "M365 Client Secret"],
  ["alibabacloud", "role", "Alibaba Cloud RAM Role"],
  ["alibabacloud", "credentials", "Alibaba Cloud Credentials"],
  ["cloudflare", "api_token", "Cloudflare API Token"],
  ["cloudflare", "api_key", "Cloudflare API Key"],
];

describe("provider label parity", () => {
  const STEPS = [
    PROVIDER_WIZARD_STEP.CONNECT,
    PROVIDER_WIZARD_STEP.CREDENTIALS,
    PROVIDER_WIZARD_STEP.TEST,
    PROVIDER_WIZARD_STEP.LAUNCH,
  ] as const;

  it("resolves the expected modal header label for every provider on every wizard step", () => {
    for (const provider of PROVIDER_TYPES) {
      for (const step of STEPS) {
        const { link } = getProviderHelpText(provider, step);
        const label = getProviderWizardDocsDestination(link);
        expect(
          label,
          `Modal header label drift for provider="${provider}" step=${step}: getProviderHelpText returned "${link}" which the parser resolved to "${label}" instead of "${EXPECTED_MODAL_HEADER_LABEL[provider]}". Check destinationLabelMap in provider-wizard-modal.utils.ts.`,
        ).toBe(EXPECTED_MODAL_HEADER_LABEL[provider]);
      }
    }
  });

  it("resolves the expected modal header label for every method-specific credentials deep link", () => {
    // Round-trip check: catches drift between the URLs in
    // `PROVIDER_CREDENTIALS_METHOD_DOCS_URL` (external-urls.ts) and the
    // section labels in `docsSectionLabelMap` (this file). A hash typo on
    // either side would otherwise slip past the individual literal-URL tests
    // in both files.
    for (const [
      provider,
      method,
      expected,
    ] of EXPECTED_METHOD_MODAL_HEADER_LABEL) {
      const { link } = getProviderHelpText(
        provider,
        PROVIDER_WIZARD_STEP.CREDENTIALS,
        method,
      );
      const label = getProviderWizardDocsDestination(link);
      expect(
        label,
        `Method-specific label drift for provider="${provider}" method="${method}": getProviderHelpText returned "${link}" which the parser resolved to "${label}" instead of "${expected}". Ensure PROVIDER_CREDENTIALS_METHOD_DOCS_URL and docsSectionLabelMap agree on the anchor.`,
      ).toBe(expected);
    }
  });
});
