import { IntegrationType } from "../types/integrations";

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
} => {
  let links = {};

  if (integrationType === undefined) {
    links = {
      cloudformation:
        "https://github.com/prowler-cloud/prowler/blob/master/permissions/templates/cloudformation/prowler-scan-role.yml",
      terraform:
        "https://github.com/prowler-cloud/prowler/tree/master/permissions/templates/terraform",
    };
  }

  if (integrationType === "aws_security_hub") {
    links = {
      cloudformation:
        "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-s3-integration/",
      terraform:
        "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-s3-integration/#terraform",
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

  return {
    ...(links as {
      cloudformation: string;
      terraform: string;
    }),
    cloudformationQuickLink: `https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate?templateURL=https%3A%2F%2Fprowler-cloud-public.s3.eu-west-1.amazonaws.com%2Fpermissions%2Ftemplates%2Faws%2Fcloudformation%2Fprowler-scan-role.yml&stackName=Prowler&param_ExternalId=${externalId}${bucketName ? `&param_EnableS3Integration=true&param_S3IntegrationBucketName=${bucketName}` : ""}`,
  };
};
