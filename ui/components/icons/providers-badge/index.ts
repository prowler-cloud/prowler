import { IconSvgProps } from "@/types";

import { AWSProviderBadge } from "./aws-provider-badge";
import { AzureProviderBadge } from "./azure-provider-badge";
import { GCPProviderBadge } from "./gcp-provider-badge";
import { GitHubProviderBadge } from "./github-provider-badge";
import { IacProviderBadge } from "./iac-provider-badge";
import { KS8ProviderBadge } from "./ks8-provider-badge";
import { M365ProviderBadge } from "./m365-provider-badge";
import { OracleCloudProviderBadge } from "./oraclecloud-provider-badge";

export {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  IacProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  OracleCloudProviderBadge,
};

// Map provider display names to their icon components
export const PROVIDER_ICONS: Record<string, React.FC<IconSvgProps>> = {
  AWS: AWSProviderBadge,
  Azure: AzureProviderBadge,
  "Google Cloud": GCPProviderBadge,
  Kubernetes: KS8ProviderBadge,
  "Microsoft 365": M365ProviderBadge,
  GitHub: GitHubProviderBadge,
  "Infrastructure as Code": IacProviderBadge,
  "Oracle Cloud Infrastructure": OracleCloudProviderBadge,
};
