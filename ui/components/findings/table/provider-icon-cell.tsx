import {
  AlibabaCloudProviderBadge,
  AWSProviderBadge,
  AzureProviderBadge,
  CloudflareProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  GoogleWorkspaceProviderBadge,
  IacProviderBadge,
  ImageProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  MongoDBAtlasProviderBadge,
  OpenStackProviderBadge,
  OracleCloudProviderBadge,
} from "@/components/icons/providers-badge";
import { cn } from "@/lib/utils";
import { ProviderType } from "@/types";

export const PROVIDER_ICONS = {
  aws: AWSProviderBadge,
  azure: AzureProviderBadge,
  gcp: GCPProviderBadge,
  kubernetes: KS8ProviderBadge,
  m365: M365ProviderBadge,
  github: GitHubProviderBadge,
  googleworkspace: GoogleWorkspaceProviderBadge,
  iac: IacProviderBadge,
  image: ImageProviderBadge,
  oraclecloud: OracleCloudProviderBadge,
  mongodbatlas: MongoDBAtlasProviderBadge,
  alibabacloud: AlibabaCloudProviderBadge,
  cloudflare: CloudflareProviderBadge,
  openstack: OpenStackProviderBadge,
} as const;

interface ProviderIconCellProps {
  provider: ProviderType;
  size?: number;
  className?: string;
}

export const ProviderIconCell = ({
  provider,
  size = 26,
  className = "size-8 rounded-md bg-white",
}: ProviderIconCellProps) => {
  const IconComponent = PROVIDER_ICONS[provider];

  if (!IconComponent) {
    return (
      <div className={cn("flex items-center justify-center", className)}>
        <span className="text-text-neutral-secondary text-xs">?</span>
      </div>
    );
  }

  return (
    <div
      className={cn(
        "flex items-center justify-center overflow-hidden",
        className,
      )}
    >
      <IconComponent width={size} height={size} />
    </div>
  );
};
