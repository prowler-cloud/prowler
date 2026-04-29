import { IntegrationType } from "../types/integrations";

// Documentation URLs
export const DOCS_URLS = {
  FINDINGS_ANALYSIS:
    "https://docs.prowler.com/user-guide/tutorials/prowler-app#step-8:-analyze-the-findings",
  AWS_ORGANIZATIONS:
    "https://docs.prowler.com/user-guide/tutorials/prowler-cloud-aws-organizations",
  ATTACK_PATHS_CUSTOM_QUERIES:
    "https://docs.prowler.com/user-guide/tutorials/prowler-app-attack-paths#writing-custom-opencypher-queries",
} as const;

// CloudFormation template URL for the ProwlerScan role.
// Also used (URL-encoded) as the templateURL param in cloudformationQuickLink
// and cloudformationOrgQuickLink below — keep both in sync.
export const PROWLER_CF_TEMPLATE_URL =
  "https://prowler-cloud-public.s3.eu-west-1.amazonaws.com/permissions/templates/aws/cloudformation/prowler-scan-role.yml";

// AWS Console URL for creating a new StackSet.
// Hardcoded to us-east-1 — StackSets are typically managed from this region.
// Users in AWS GovCloud or China partitions would need different URLs.
export const STACKSET_CONSOLE_URL =
  "https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacksets/create";

export const getProviderHelpText = (provider: string) => {
  switch (provider) {
    case "aws":
      return {
        text: "Need help connecting your AWS account?",
        link: "https://goto.prowler.com/provider-aws",
      };
    case "azure":
      return {
        text: "Need help connecting your Azure subscription?",
        link: "https://goto.prowler.com/provider-azure",
      };
    case "m365":
      return {
        text: "Need help connecting your Microsoft 365 account?",
        link: "https://goto.prowler.com/provider-m365",
      };
    case "gcp":
      return {
        text: "Need help connecting your GCP project?",
        link: "https://goto.prowler.com/provider-gcp",
      };
    case "kubernetes":
      return {
        text: "Need help connecting your Kubernetes cluster?",
        link: "https://goto.prowler.com/provider-k8s",
      };
    case "github":
      return {
        text: "Need help connecting your GitHub account?",
        link: "https://goto.prowler.com/provider-github",
      };
    case "iac":
      return {
        text: "Need help scanning your Infrastructure as Code repository?",
        link: "https://goto.prowler.com/provider-iac",
      };
    case "image":
      return {
        text: "Need help scanning your container registry?",
        link: "https://goto.prowler.com/provider-image",
      };
    case "oraclecloud":
      return {
        text: "Need help connecting your Oracle Cloud account?",
        link: "https://goto.prowler.com/provider-oraclecloud",
      };
    case "mongodbatlas":
      return {
        text: "Need help connecting your MongoDB Atlas organization?",
        link: "https://goto.prowler.com/provider-mongodbatlas",
      };
    case "alibabacloud":
      return {
        text: "Need help connecting your Alibaba Cloud account?",
        link: "https://goto.prowler.com/provider-alibabacloud",
      };
    case "cloudflare":
      return {
        text: "Need help connecting your Cloudflare account?",
        link: "https://goto.prowler.com/provider-cloudflare",
      };
    case "openstack":
      return {
        text: "Need help connecting your OpenStack cloud?",
        link: "https://goto.prowler.com/provider-openstack",
      };
    case "googleworkspace":
      return {
        text: "Need help connecting your Google Workspace account?",
        link: "https://goto.prowler.com/provider-googleworkspace",
      };
    case "vercel":
      return {
        text: "Need help connecting your Vercel team?",
        link: "https://goto.prowler.com/provider-vercel",
      };
    default:
      return {
        text: "How to setup a provider?",
        link: "https://goto.prowler.com/provider-help",
      };
  }
};

export const getAWSCredentialsTemplateLinks = (
  externalId: string,
  bucketName?: string,
  integrationType?: IntegrationType,
): {
  cloudformation: string;
  terraform: string;
  cloudformationQuickLink: string;
  cloudformationOrgQuickLink: string;
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

  const encodedTemplateUrl = encodeURIComponent(PROWLER_CF_TEMPLATE_URL);
  const cfBaseUrl =
    "https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate";
  const s3Params = bucketName
    ? `&param_EnableS3Integration=true&param_S3IntegrationBucketName=${bucketName}`
    : "";

  return {
    ...(links as {
      cloudformation: string;
      terraform: string;
    }),
    cloudformationQuickLink:
      `${cfBaseUrl}?templateURL=${encodedTemplateUrl}` +
      `&stackName=Prowler&param_ExternalId=${externalId}${s3Params}`,
    cloudformationOrgQuickLink:
      `${cfBaseUrl}?templateURL=${encodedTemplateUrl}` +
      `&stackName=Prowler&param_ExternalId=${externalId}` +
      `&param_EnableOrganizations=true${s3Params}`,
  };
};
