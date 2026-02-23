import type { FC } from "react";

import { IconSvgProps } from "@/types";

import { AlibabaCloudProviderBadge } from "./alibabacloud-provider-badge";
import { AWSProviderBadge } from "./aws-provider-badge";
import { AzureProviderBadge } from "./azure-provider-badge";
import { CloudflareProviderBadge } from "./cloudflare-provider-badge";
import { GCPProviderBadge } from "./gcp-provider-badge";
import { GitHubProviderBadge } from "./github-provider-badge";
import { IacProviderBadge } from "./iac-provider-badge";
import { KS8ProviderBadge } from "./ks8-provider-badge";
import { M365ProviderBadge } from "./m365-provider-badge";
import { MongoDBAtlasProviderBadge } from "./mongodbatlas-provider-badge";
import { OpenStackProviderBadge } from "./openstack-provider-badge";
import { OracleCloudProviderBadge } from "./oraclecloud-provider-badge";

export {
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
};

// Map provider display names to their icon components
export const PROVIDER_ICONS: Record<string, FC<IconSvgProps>> = {
  AWS: AWSProviderBadge,
  Azure: AzureProviderBadge,
  "Google Cloud": GCPProviderBadge,
  Kubernetes: KS8ProviderBadge,
  "Microsoft 365": M365ProviderBadge,
  GitHub: GitHubProviderBadge,
  "Infrastructure as Code": IacProviderBadge,
  "Oracle Cloud Infrastructure": OracleCloudProviderBadge,
  "MongoDB Atlas": MongoDBAtlasProviderBadge,
  "Alibaba Cloud": AlibabaCloudProviderBadge,
  Cloudflare: CloudflareProviderBadge,
  OpenStack: OpenStackProviderBadge,
};
