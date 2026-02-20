import {
  AlibabaCloudProviderBadge,
  AWSProviderBadge,
  AzureProviderBadge,
  CloudflareProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  IacProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  MongoDBAtlasProviderBadge,
  OpenStackProviderBadge,
  OracleCloudProviderBadge,
} from "@/components/icons/providers-badge";
import { ProviderType } from "@/types";

export const getProviderLogo = (provider: ProviderType) => {
  switch (provider) {
    case "aws":
      return <AWSProviderBadge width={35} height={35} />;
    case "azure":
      return <AzureProviderBadge width={35} height={35} />;
    case "gcp":
      return <GCPProviderBadge width={35} height={35} />;
    case "kubernetes":
      return <KS8ProviderBadge width={35} height={35} />;
    case "m365":
      return <M365ProviderBadge width={35} height={35} />;
    case "github":
      return <GitHubProviderBadge width={35} height={35} />;
    case "iac":
      return <IacProviderBadge width={35} height={35} />;
    case "oraclecloud":
      return <OracleCloudProviderBadge width={35} height={35} />;
    case "mongodbatlas":
      return <MongoDBAtlasProviderBadge width={35} height={35} />;
    case "alibabacloud":
      return <AlibabaCloudProviderBadge width={35} height={35} />;
    case "cloudflare":
      return <CloudflareProviderBadge width={35} height={35} />;
    case "openstack":
      return <OpenStackProviderBadge width={35} height={35} />;
    default:
      return null;
  }
};

export const getProviderName = (provider: ProviderType): string => {
  switch (provider) {
    case "aws":
      return "Amazon Web Services";
    case "azure":
      return "Microsoft Azure";
    case "gcp":
      return "Google Cloud Platform";
    case "kubernetes":
      return "Kubernetes";
    case "m365":
      return "Microsoft 365";
    case "github":
      return "GitHub";
    case "iac":
      return "Infrastructure as Code";
    case "oraclecloud":
      return "Oracle Cloud Infrastructure";
    case "mongodbatlas":
      return "MongoDB Atlas";
    case "alibabacloud":
      return "Alibaba Cloud";
    case "cloudflare":
      return "Cloudflare";
    case "openstack":
      return "OpenStack";
    default:
      return "Unknown Provider";
  }
};
