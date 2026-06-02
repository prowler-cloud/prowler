"use client";

import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { type ComponentType, lazy, Suspense } from "react";

import {
  Badge,
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/shadcn";
import { cn } from "@/lib/utils";
import type { ProviderType } from "@/types/providers";

type IconProps = { width: number; height: number };

const IconPlaceholder = ({ width, height }: IconProps) => (
  <div style={{ width, height }} />
);

// Lazy-load every provider badge so the ~16 SVGs ship in a single deferred
// chunk instead of being eagerly bundled wherever a selector is imported.
const AWSProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.AWSProviderBadge,
  })),
);
const AzureProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.AzureProviderBadge,
  })),
);
const GCPProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.GCPProviderBadge,
  })),
);
const KS8ProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.KS8ProviderBadge,
  })),
);
const M365ProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.M365ProviderBadge,
  })),
);
const GitHubProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.GitHubProviderBadge,
  })),
);
const GoogleWorkspaceProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.GoogleWorkspaceProviderBadge,
  })),
);
const IacProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.IacProviderBadge,
  })),
);
const ImageProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.ImageProviderBadge,
  })),
);
const OracleCloudProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.OracleCloudProviderBadge,
  })),
);
const MongoDBAtlasProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.MongoDBAtlasProviderBadge,
  })),
);
const AlibabaCloudProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.AlibabaCloudProviderBadge,
  })),
);
const CloudflareProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.CloudflareProviderBadge,
  })),
);
const OpenStackProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.OpenStackProviderBadge,
  })),
);
const VercelProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.VercelProviderBadge,
  })),
);
const OktaProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.OktaProviderBadge,
  })),
);

/**
 * Single source of truth mapping each provider type to its human-readable
 * label and (lazy) badge component. Shared by the account and provider-type
 * selectors so both stay in sync on labels, icons, and sizing.
 */
export const PROVIDER_TYPE_DATA: Record<
  ProviderType,
  { label: string; icon: ComponentType<IconProps> }
> = {
  aws: { label: "Amazon Web Services", icon: AWSProviderBadge },
  azure: { label: "Microsoft Azure", icon: AzureProviderBadge },
  gcp: { label: "Google Cloud Platform", icon: GCPProviderBadge },
  kubernetes: { label: "Kubernetes", icon: KS8ProviderBadge },
  m365: { label: "Microsoft 365", icon: M365ProviderBadge },
  github: { label: "GitHub", icon: GitHubProviderBadge },
  googleworkspace: {
    label: "Google Workspace",
    icon: GoogleWorkspaceProviderBadge,
  },
  iac: { label: "Infrastructure as Code", icon: IacProviderBadge },
  image: { label: "Container Registry", icon: ImageProviderBadge },
  oraclecloud: {
    label: "Oracle Cloud Infrastructure",
    icon: OracleCloudProviderBadge,
  },
  mongodbatlas: { label: "MongoDB Atlas", icon: MongoDBAtlasProviderBadge },
  alibabacloud: { label: "Alibaba Cloud", icon: AlibabaCloudProviderBadge },
  cloudflare: { label: "Cloudflare", icon: CloudflareProviderBadge },
  openstack: { label: "OpenStack", icon: OpenStackProviderBadge },
  vercel: { label: "Vercel", icon: VercelProviderBadge },
  okta: { label: "Okta", icon: OktaProviderBadge },
};

interface ProviderTypeIconProps {
  type: ProviderType;
  size?: number;
}

/** Renders a single provider-type badge with a sized placeholder fallback. */
export const ProviderTypeIcon = ({
  type,
  size = 18,
}: ProviderTypeIconProps) => {
  const Icon = PROVIDER_TYPE_DATA[type].icon;
  return (
    <Suspense fallback={<IconPlaceholder width={size} height={size} />}>
      <Icon width={size} height={size} />
    </Suspense>
  );
};

export interface ProviderTypeIconStackItem {
  /** Stable React key (account id for accounts, provider type for types). */
  key: string;
  type: ProviderType;
  /** Text shown on hover to disambiguate the icon (e.g. an account UID). */
  tooltip?: string;
}

interface ProviderTypeIconStackProps {
  items: ProviderTypeIconStackItem[];
  max?: number;
  size?: number;
  className?: string;
}

/** Icon wrapped in a portalled tooltip so it isn't clipped by the trigger. */
const IconWithTooltip = ({
  item,
  size,
}: {
  item: ProviderTypeIconStackItem;
  size: number;
}) => {
  const icon = (
    <span className="inline-flex shrink-0">
      <ProviderTypeIcon type={item.type} size={size} />
    </span>
  );

  if (!item.tooltip) return icon;

  return (
    <Tooltip>
      <TooltipTrigger asChild>{icon}</TooltipTrigger>
      <TooltipPrimitive.Portal>
        <TooltipContent side="top">{item.tooltip}</TooltipContent>
      </TooltipPrimitive.Portal>
    </Tooltip>
  );
};

/**
 * Renders up to `max` provider-type icons followed by a `+N` badge for the
 * remainder. Each icon shows its `tooltip` on hover. Items are rendered as
 * passed (one per selection) — callers decide whether to dedupe.
 */
export const ProviderTypeIconStack = ({
  items,
  max = 3,
  size = 18,
  className,
}: ProviderTypeIconStackProps) => {
  const visible = items.slice(0, max);
  const overflow = items.slice(max);
  const overflowLabel = overflow
    .map((item) => item.tooltip)
    .filter(Boolean)
    .join(", ");

  return (
    <TooltipProvider delayDuration={150}>
      <span className={cn("flex shrink-0 items-center gap-1", className)}>
        <span className="flex items-center gap-1">
          {visible.map((item) => (
            <IconWithTooltip key={item.key} item={item} size={size} />
          ))}
        </span>
        {overflow.length > 0 && (
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge
                variant="tag"
                className="px-1.5 py-0.5 text-xs font-medium"
              >
                +{overflow.length}
              </Badge>
            </TooltipTrigger>
            {overflowLabel && (
              <TooltipPrimitive.Portal>
                <TooltipContent side="top" className="max-w-xs">
                  {overflowLabel}
                </TooltipContent>
              </TooltipPrimitive.Portal>
            )}
          </Tooltip>
        )}
      </span>
    </TooltipProvider>
  );
};
