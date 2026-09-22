"use client";

import {
  BadgeCheck,
  Check,
  ClipboardCheck,
  Download,
  ListChecks,
  Package,
  ShieldCheck,
  Tag,
} from "lucide-react";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { ProwlerShort } from "@/components/icons/prowler/ProwlerIcons";
import {
  Avatar,
  AvatarImage,
  AvatarFallback,
} from "@/components/shadcn/avatar/avatar";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { getRegistryNotInstallableMessage } from "@/lib/registry/installability";
import { cn } from "@/lib/utils";
import { getProviderDisplayName, isKnownProviderType } from "@/types/providers";
import type { RegistryArtifactOwner } from "@/types/registry";

import {
  REGISTRY_CAPABILITY_LABELS,
  type RegistryMarketplaceArtifact,
} from "./registry-explorer.model";

interface RegistryArtifactCardProps {
  artifact: RegistryMarketplaceArtifact;
  pendingAddName?: string;
  onAdd: () => void;
  onRemove: (trigger: HTMLButtonElement | null) => void;
}

function capabilitySummary(artifact: RegistryMarketplaceArtifact) {
  const labels = [
    artifact.hasProvider && REGISTRY_CAPABILITY_LABELS.provider,
    artifact.hasChecks && REGISTRY_CAPABILITY_LABELS.checks,
    artifact.hasCompliance && REGISTRY_CAPABILITY_LABELS.compliance,
  ].filter((label) => label !== false);
  return labels.join(", ");
}

/**
 * Maximum provider logos rendered in the footer cluster before collapsing
 * the remainder into a "+N" overflow badge (registry.dev card reference).
 */
const MAX_PROVIDER_LOGOS = 4;

const PROVIDER_LIST_FORMAT = new Intl.ListFormat("en", {
  style: "long",
  type: "conjunction",
});

interface RegistryProviderClusterProps {
  providers: string[];
}

function RegistryProviderCluster({ providers }: RegistryProviderClusterProps) {
  if (providers.length === 0) return null;

  const displayNames = providers.map(getProviderDisplayName);
  const visibleProviders = providers.slice(0, MAX_PROVIDER_LOGOS);
  const overflowCount = providers.length - visibleProviders.length;

  return (
    <span className="flex items-center gap-1.5">
      {/* Icons alone must never be the only carrier of the provider names. */}
      <span className="sr-only">
        {providers.length === 1
          ? `Provider: ${displayNames[0]}`
          : `Providers: ${displayNames.join(", ")}`}
      </span>
      {providers.length > 1 && (
        <span aria-hidden className="text-text-neutral-secondary text-xs">
          {providers.length} providers
        </span>
      )}
      <span className="flex items-center gap-1">
        {visibleProviders.map((provider) => (
          <Tooltip key={provider} delayDuration={150}>
            <TooltipTrigger asChild>
              <span
                role="img"
                aria-label={getProviderDisplayName(provider)}
                tabIndex={0}
                className="focus-visible:outline-button-primary inline-flex shrink-0 rounded-sm focus-visible:outline-2 focus-visible:outline-offset-2"
              >
                {isKnownProviderType(provider) ? (
                  <ProviderTypeIcon size={16} type={provider} />
                ) : (
                  <Badge size="sm" variant="tag">
                    {getProviderDisplayName(provider)}
                  </Badge>
                )}
              </span>
            </TooltipTrigger>
            <TooltipContent side="top">
              {getProviderDisplayName(provider)}
            </TooltipContent>
          </Tooltip>
        ))}
      </span>
      {overflowCount > 0 && (
        <span aria-hidden className="text-text-neutral-secondary text-xs">
          +{overflowCount}
        </span>
      )}
    </span>
  );
}

interface RegistryExtendedProvidersProps {
  slugs: string[];
}

/** The only thing explaining an install that shows no provider type. */
function RegistryExtendedProviders({ slugs }: RegistryExtendedProvidersProps) {
  if (slugs.length === 0) return null;

  return (
    <p className="text-text-neutral-secondary text-xs">
      Adds checks to your{" "}
      {PROVIDER_LIST_FORMAT.format(slugs.map(getProviderDisplayName))} scans.
    </p>
  );
}

interface RegistryOwnerRowProps {
  isOfficial: boolean;
  isVerified: boolean;
  owner?: RegistryArtifactOwner;
}

function RegistryOwnerRow({
  isOfficial,
  isVerified,
  owner,
}: RegistryOwnerRowProps) {
  if (!owner && !isOfficial && !isVerified) return null;

  return (
    <div className="flex flex-wrap items-center gap-2">
      {owner &&
        (owner.name.trim().toLowerCase() === "prowler" ? (
          <ProwlerShort aria-label="Prowler" role="img" size={20} />
        ) : (
          <span className="flex min-w-0 items-center gap-2">
            <Avatar aria-hidden className="size-5">
              <AvatarImage alt="" src={owner.logoUrl} />
              <AvatarFallback>{owner.name.charAt(0)}</AvatarFallback>
            </Avatar>
            <span className="text-text-neutral-secondary truncate text-xs">
              {owner.name}
            </span>
          </span>
        ))}
      {isOfficial && (
        <Badge variant="tag">
          <ShieldCheck aria-hidden />
          Official
        </Badge>
      )}
      {isVerified && (
        <Badge variant="success">
          <BadgeCheck aria-hidden />
          Verified
        </Badge>
      )}
    </div>
  );
}

interface RegistryArtifactMetadataProps {
  complianceCount?: number;
  checkCount?: number;
  version?: string;
  isAdded?: boolean;
  availableVersion?: string;
  downloads?: number;
}

function RegistryArtifactMetadata({
  complianceCount,
  checkCount,
  version,
  isAdded,
  availableVersion,
  downloads,
}: RegistryArtifactMetadataProps) {
  const items = [
    {
      label: REGISTRY_CAPABILITY_LABELS.compliance,
      value: complianceCount,
      icon: ClipboardCheck,
    },
    {
      label: REGISTRY_CAPABILITY_LABELS.checks,
      value: checkCount,
      icon: ListChecks,
    },
    { label: isAdded ? "Installed" : "Version", value: version, icon: Tag },
    { label: "Available", value: availableVersion, icon: Tag },
    { label: "Downloads", value: downloads, icon: Download },
  ].filter(({ value }) => value !== undefined && value !== "");

  if (items.length === 0) return null;

  return (
    <div className="@container">
      <dl
        role="group"
        aria-label="Artifact metadata"
        className={cn(
          "border-border-neutral-tertiary grid grid-cols-1 gap-x-4 gap-y-3 border-t pt-3",
          items.length > 1 && "grid-cols-2",
          items.length === 3 && "@sm:grid-cols-3",
          items.length === 4 && "@sm:grid-cols-4",
          items.length === 5 && "@sm:grid-cols-3",
        )}
      >
        {items.map(({ label, value, icon: Icon }) => (
          <div key={label} className="min-w-0 space-y-1">
            <dt className="text-text-neutral-secondary flex items-center gap-1.5 text-xs">
              <Icon
                aria-hidden
                className="text-text-neutral-tertiary size-3.5 shrink-0"
              />
              {label}
            </dt>
            <dd
              className={cn(
                "text-text-neutral-primary text-sm leading-5 font-medium wrap-anywhere tabular-nums",
                Icon === Tag && "font-mono",
              )}
            >
              {typeof value === "number"
                ? value.toLocaleString("en-US")
                : value}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export function RegistryArtifactCard({
  artifact,
  pendingAddName,
  onAdd,
  onRemove,
}: RegistryArtifactCardProps) {
  const displayName = artifact.name ?? artifact.normalizedName;
  const subtitle = [
    artifact.providers.map(getProviderDisplayName).join(", "),
    capabilitySummary(artifact),
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <Card className="h-full gap-3" padding="md" variant="inner">
      <div className="flex items-start gap-3">
        <span
          aria-hidden
          className="bg-bg-neutral-tertiary text-text-neutral-secondary flex size-10 shrink-0 items-center justify-center overflow-hidden rounded-lg"
        >
          {/* Artifacts can span several providers, so the header shows a
              neutral package mark instead of any single provider logo. */}
          <Package size={26} />
        </span>
        <div className="min-w-0">
          <p className="text-text-neutral-primary truncate text-sm font-semibold">
            {displayName}
          </p>
          {subtitle && (
            <p className="text-text-neutral-secondary truncate text-xs">
              {subtitle}
            </p>
          )}
        </div>
      </div>
      {artifact.description && (
        <p className="text-text-neutral-secondary line-clamp-2 text-sm">
          {artifact.description}
        </p>
      )}
      <div className="mt-auto space-y-3">
        <RegistryOwnerRow
          isOfficial={artifact.isOfficial}
          isVerified={artifact.isVerified}
          owner={artifact.owners[0]}
        />
        <RegistryArtifactMetadata
          complianceCount={artifact.complianceCount}
          checkCount={artifact.checkCount}
          version={
            artifact.isAdded
              ? artifact.resolvedVersion || "Unknown"
              : artifact.latestVersion
          }
          isAdded={artifact.isAdded}
          availableVersion={
            artifact.isAdded &&
            artifact.latestVersion !== artifact.resolvedVersion
              ? artifact.latestVersion
              : undefined
          }
          downloads={artifact.isBuiltin ? undefined : artifact.totalDownloads}
        />
        <RegistryExtendedProviders slugs={artifact.extendsProviderSlugs} />
        {!artifact.isAdded &&
          !artifact.isInstallable &&
          !artifact.isBuiltin && (
            <p className="text-text-neutral-secondary text-xs">
              {getRegistryNotInstallableMessage(artifact.notInstallableReason)}
            </p>
          )}
        <div className="flex flex-wrap items-center gap-3">
          <RegistryProviderCluster providers={artifact.providers} />
          <span className="ml-auto flex flex-wrap items-center justify-end gap-2">
            {artifact.isBuiltin && (
              <Badge aria-label="Built in" role="status" variant="tag">
                Built in
              </Badge>
            )}
            {artifact.isAdded ? (
              <>
                {artifact.updateAvailable && artifact.isInstallable ? (
                  <Button
                    aria-label={`Update ${displayName} to ${artifact.latestVersion}`}
                    disabled={Boolean(pendingAddName)}
                    onClick={onAdd}
                    size="sm"
                    type="button"
                  >
                    {pendingAddName === artifact.normalizedName
                      ? "Updating…"
                      : "Update"}
                  </Button>
                ) : (
                  <Badge variant="outline">
                    <Check aria-hidden />
                    Added
                  </Badge>
                )}
                <Button
                  aria-label={`Remove ${displayName}`}
                  disabled={pendingAddName === artifact.normalizedName}
                  onClick={(event) => onRemove(event.currentTarget)}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  Remove
                </Button>
              </>
            ) : artifact.isInstallable ? (
              <Button
                aria-label={`Add ${displayName}`}
                disabled={Boolean(pendingAddName)}
                onClick={onAdd}
                size="sm"
                type="button"
              >
                {pendingAddName === artifact.normalizedName ? "Adding…" : "Add"}
              </Button>
            ) : null}
          </span>
        </div>
      </div>
    </Card>
  );
}

interface RegistryTenantArtifactCardProps {
  extendsProviderSlugs?: string[];
  normalizedName: string;
  onRemove: (trigger: HTMLButtonElement | null) => void;
  resolvedVersion?: string;
}

export function RegistryTenantArtifactCard({
  extendsProviderSlugs = [],
  normalizedName,
  onRemove,
  resolvedVersion,
}: RegistryTenantArtifactCardProps) {
  return (
    <Card className="h-full gap-3" padding="md" variant="inner">
      <div className="flex items-start gap-3">
        <span
          aria-hidden
          className="bg-bg-neutral-tertiary text-text-neutral-secondary flex size-10 shrink-0 items-center justify-center overflow-hidden rounded-lg"
        >
          {/* Tenant artifacts carry no provider metadata; the neutral package
              mark matches the marketplace card header. */}
          <Package size={26} />
        </span>
        <div className="min-w-0">
          <p className="text-text-neutral-primary truncate text-sm font-semibold">
            {normalizedName}
          </p>
        </div>
      </div>
      <p className="text-text-neutral-secondary text-sm">
        Installed in this workspace. Catalog metadata is not available for this
        artifact.
      </p>
      <div className="mt-auto space-y-3">
        <RegistryArtifactMetadata
          isAdded
          version={resolvedVersion || "Unknown"}
        />
        <RegistryExtendedProviders slugs={extendsProviderSlugs} />
        <div className="flex justify-end">
          <Button
            aria-label={`Remove ${normalizedName}`}
            onClick={(event) => onRemove(event.currentTarget)}
            size="sm"
            type="button"
            variant="outline"
          >
            Remove
          </Button>
        </div>
      </div>
    </Card>
  );
}
