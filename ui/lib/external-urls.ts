import type { IntegrationType } from "../types/integrations";
import {
  PROVIDER_WIZARD_STEP,
  type ProviderWizardStep,
} from "../types/provider-wizard";

// Documentation URLs
export const DOCS_URLS = {
  FINDINGS_ANALYSIS:
    "https://docs.prowler.com/user-guide/tutorials/prowler-app#step-8:-analyze-the-findings",
  FINDINGS_INGESTION:
    "https://docs.prowler.com/user-guide/tutorials/prowler-app-import-findings",
  FINDINGS_TRIAGE:
    "https://docs.prowler.com/user-guide/tutorials/prowler-app-findings-triage",
  AWS_ORGANIZATIONS:
    "https://docs.prowler.com/user-guide/tutorials/prowler-cloud-aws-organizations",
  ALERTS: "https://docs.prowler.com/user-guide/tutorials/prowler-app-alerts",
  SCAN_CONFIGURATION:
    "https://docs.prowler.com/user-guide/tutorials/prowler-app-scan-configuration",
  ATTACK_PATHS_CUSTOM_QUERIES:
    "https://docs.prowler.com/user-guide/tutorials/prowler-app-attack-paths#writing-custom-opencypher-queries",
  AI_AGENTS: "https://docs.prowler.com/user-guide/ai-agents/",
} as const;

// CloudFormation template URL for the ProwlerScan role.
// Also used (URL-encoded) as the templateURL param in the quick-create links
// built by getAWSCredentialsTemplateLinks and getAWSOrgDeploymentQuickLink below.
export const PROWLER_CF_TEMPLATE_URL =
  "https://prowler-cloud-public.s3.eu-west-1.amazonaws.com/permissions/templates/aws/cloudformation/prowler-scan-role.yml";

// Prowler Cloud billing/subscription management page.
export const BILLING_URL = "https://cloud.prowler.com/billing";

// Base URL for the CloudFormation "quick create stack" console flow.
// Hardcoded to us-east-1 because the public template is hosted for that flow.
const CF_QUICKCREATE_BASE_URL =
  "https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate";

export interface AWSOrgDeploymentQuickLinkParams {
  externalId: string;
  organizationalUnitId: string;
  deployFromDelegatedAdmin?: boolean;
}

const buildCloudFormationQuickCreateLink = (
  parameters: Record<string, string>,
): string => {
  const searchParams = new URLSearchParams({
    templateURL: PROWLER_CF_TEMPLATE_URL,
    stackName: "Prowler",
    ...parameters,
  });

  return `${CF_QUICKCREATE_BASE_URL}?${searchParams.toString()}`;
};

// Shortlinks are used for all wizard steps except credentials so link
// ownership stays with the docs/marketing team: they can retarget
// destinations from the shortener panel without a UI PR.
const PROVIDER_DOCS_SHORTLINK: Record<string, string> = {
  aws: "https://goto.prowler.com/provider-aws",
  azure: "https://goto.prowler.com/provider-azure",
  m365: "https://goto.prowler.com/provider-m365",
  gcp: "https://goto.prowler.com/provider-gcp",
  kubernetes: "https://goto.prowler.com/provider-k8s",
  github: "https://goto.prowler.com/provider-github",
  iac: "https://goto.prowler.com/provider-iac",
  image: "https://goto.prowler.com/provider-image",
  oraclecloud: "https://goto.prowler.com/provider-oraclecloud",
  mongodbatlas: "https://goto.prowler.com/provider-mongodbatlas",
  alibabacloud: "https://goto.prowler.com/provider-alibabacloud",
  cloudflare: "https://goto.prowler.com/provider-cloudflare",
  openstack: "https://goto.prowler.com/provider-openstack",
  googleworkspace: "https://goto.prowler.com/provider-googleworkspace",
  vercel: "https://goto.prowler.com/provider-vercel",
  okta: "https://goto.prowler.com/provider-okta",
};

// On the credentials step we bypass the shortener and point straight to the
// dedicated authentication docs page for each provider. That page is a full
// guide covering every supported auth method (required permissions, setup
// steps, troubleshooting) instead of the short summary block on the
// getting-started page — much more useful the moment the user is filling in
// the form. Kubernetes has no dedicated authentication.mdx: its auth setup
// lives inline in getting-started-k8s.mdx, so it falls back to the shortlink
// with an anchor to that section.
const PROVIDER_AUTHENTICATION_DOCS_URL: Record<string, string> = {
  aws: "https://docs.prowler.com/user-guide/providers/aws/authentication",
  azure: "https://docs.prowler.com/user-guide/providers/azure/authentication",
  m365: "https://docs.prowler.com/user-guide/providers/microsoft365/authentication",
  gcp: "https://docs.prowler.com/user-guide/providers/gcp/authentication",
  github: "https://docs.prowler.com/user-guide/providers/github/authentication",
  iac: "https://docs.prowler.com/user-guide/providers/iac/authentication",
  image: "https://docs.prowler.com/user-guide/providers/image/authentication",
  oraclecloud:
    "https://docs.prowler.com/user-guide/providers/oci/authentication",
  mongodbatlas:
    "https://docs.prowler.com/user-guide/providers/mongodbatlas/authentication",
  alibabacloud:
    "https://docs.prowler.com/user-guide/providers/alibabacloud/authentication",
  cloudflare:
    "https://docs.prowler.com/user-guide/providers/cloudflare/authentication",
  openstack:
    "https://docs.prowler.com/user-guide/providers/openstack/authentication",
  googleworkspace:
    "https://docs.prowler.com/user-guide/providers/googleworkspace/authentication",
  vercel: "https://docs.prowler.com/user-guide/providers/vercel/authentication",
  okta: "https://docs.prowler.com/user-guide/providers/okta/authentication",
};

// Fallback anchor for providers without a dedicated authentication.mdx page
// (currently only Kubernetes). The anchor is set explicitly on the provider's
// getting-started page so it stays stable if the heading is reworded.
const CREDENTIALS_DOCS_ANCHOR = "#authentication";

const PROVIDER_HELP_FALLBACK_URL = "https://goto.prowler.com/provider-help";

const resolveDocsLink = (provider: string, step?: ProviderWizardStep) => {
  const shortlink = PROVIDER_DOCS_SHORTLINK[provider];

  if (step === PROVIDER_WIZARD_STEP.CREDENTIALS) {
    const authUrl = PROVIDER_AUTHENTICATION_DOCS_URL[provider];
    if (authUrl) return authUrl;
    // Providers without a dedicated auth page (Kubernetes today) deep-link
    // into the auth section of their getting-started page instead.
    if (shortlink) return `${shortlink}${CREDENTIALS_DOCS_ANCHOR}`;
  }

  return shortlink;
};

const PROVIDER_HELP_TEXT: Record<string, string> = {
  aws: "Need help connecting your AWS account?",
  azure: "Need help connecting your Azure subscription?",
  m365: "Need help connecting your Microsoft 365 account?",
  gcp: "Need help connecting your GCP project?",
  kubernetes: "Need help connecting your Kubernetes cluster?",
  github: "Need help connecting your GitHub account?",
  iac: "Need help scanning your Infrastructure as Code repository?",
  image: "Need help scanning your container registry?",
  oraclecloud: "Need help connecting your Oracle Cloud account?",
  mongodbatlas: "Need help connecting your MongoDB Atlas organization?",
  alibabacloud: "Need help connecting your Alibaba Cloud account?",
  cloudflare: "Need help connecting your Cloudflare account?",
  openstack: "Need help connecting your OpenStack cloud?",
  googleworkspace: "Need help connecting your Google Workspace account?",
  vercel: "Need help connecting your Vercel team?",
  okta: "Need help connecting your Okta organization?",
};

export const getProviderHelpText = (
  provider: string,
  step?: ProviderWizardStep,
) => {
  const link = resolveDocsLink(provider, step);

  if (!link) {
    // Unknown provider: hand off to the generic help shortlink instead of
    // deep-linking into a page that may not exist.
    return {
      text: "How to setup a provider?",
      link: PROVIDER_HELP_FALLBACK_URL,
    };
  }

  return {
    text: PROVIDER_HELP_TEXT[provider] ?? "Need help connecting your provider?",
    link,
  };
};

export const getAWSCredentialsTemplateLinks = (
  externalId: string,
  bucketName?: string,
  integrationType?: IntegrationType,
  bucketAccountId?: string,
): {
  cloudformation: string;
  terraform: string;
  cloudformationQuickLink: string;
} => {
  let links = {};

  if (integrationType === undefined || integrationType === "aws_security_hub") {
    links = {
      cloudformation:
        "https://github.com/prowler-cloud/prowler/blob/master/permissions/templates/cloudformation/prowler-scan-role.yml",
      terraform:
        "https://github.com/prowler-cloud/prowler/tree/master/permissions/templates/terraform",
    };
  }

  if (integrationType === "amazon_s3") {
    links = {
      cloudformation:
        "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-s3-integration/",
      terraform:
        "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-s3-integration/#terraform",
    };
  }

  // The template requires S3IntegrationBucketAccountId (owner account of the
  // bucket) whenever EnableS3Integration is true. Only enable S3 when both the
  // bucket name and its account id are known, otherwise an incomplete link
  // would fail stack validation on the quick-create flow (reachable from the
  // edit-credentials flow, where the account id can resolve to an empty value).
  const parameters: Record<string, string> = {
    param_ExternalId: externalId,
  };

  if (bucketName && bucketAccountId) {
    parameters.param_EnableS3Integration = "true";
    parameters.param_S3IntegrationBucketName = bucketName;
    parameters.param_S3IntegrationBucketAccountId = bucketAccountId;
  }

  return {
    ...(links as {
      cloudformation: string;
      terraform: string;
    }),
    cloudformationQuickLink: buildCloudFormationQuickCreateLink(parameters),
  };
};

// Builds the CloudFormation quick-create link that onboards an entire AWS
// Organization in a single stack: it creates the ProwlerScan role in the
// account launching the stack (DeployLocalRole) and a service-managed StackSet
// that rolls the role out to the member accounts under the given OU/root
// (DeployStackSet). By default the stack is launched from the management
// account; set deployFromDelegatedAdmin when launching from a delegated
// administrator account instead, where the local role lands in that account.
export const getAWSOrgDeploymentQuickLink = ({
  externalId,
  organizationalUnitId,
  deployFromDelegatedAdmin = false,
}: AWSOrgDeploymentQuickLinkParams): string => {
  const parameters: Record<string, string> = {
    param_ExternalId: externalId,
    param_EnableOrganizations: "true",
    param_DeployLocalRole: "true",
    param_DeployStackSet: "true",
    param_AWSOrganizationalUnitId: organizationalUnitId,
  };

  if (deployFromDelegatedAdmin) {
    parameters.param_DeployFromDelegatedAdmin = "true";
  }

  return buildCloudFormationQuickCreateLink(parameters);
};
