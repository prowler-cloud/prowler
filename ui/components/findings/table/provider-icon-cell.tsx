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

export const PROVIDER_ICONS = {
  aws: AWSProviderBadge,
  azure: AzureProviderBadge,
  gcp: GCPProviderBadge,
  kubernetes: KS8ProviderBadge,
  m365: M365ProviderBadge,
  github: GitHubProviderBadge,
  iac: IacProviderBadge,
  oraclecloud: OracleCloudProviderBadge,
  mongodbatlas: MongoDBAtlasProviderBadge,
  alibabacloud: AlibabaCloudProviderBadge,
  cloudflare: CloudflareProviderBadge,
  openstack: OpenStackProviderBadge,
} as const;

interface ProviderIconCellProps {
  provider: ProviderType;
  size?: number;
}

export const ProviderIconCell = ({
  provider,
  size = 26,
}: ProviderIconCellProps) => {
  const IconComponent = PROVIDER_ICONS[provider];

  if (!IconComponent) {
    return (
      <div className="flex size-8 items-center justify-center rounded-md bg-white">
        <span className="text-text-neutral-secondary text-xs">?</span>
      </div>
    );
  }

  return (
    <div className="flex size-8 items-center justify-center overflow-hidden rounded-md bg-white">
      <IconComponent width={size} height={size} />
    </div>
  );
};
