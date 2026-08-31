"use client";

import {
  BadgeCheck,
  Check,
  Download,
  Package,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import { getProviderDisplayName, isKnownProviderType } from "@/types/providers";
import type { RegistryArtifactOwner } from "@/types/registry";

import {
  REGISTRY_CAPABILITY_LABELS,
  type RegistryMarketplaceArtifact,
} from "./registry-explorer.model";

interface RegistryArtifactCardProps {
  artifact: RegistryMarketplaceArtifact;
  isAddPending: boolean;
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
      <span aria-hidden className="flex items-center gap-1">
        {visibleProviders.map((provider) =>
          isKnownProviderType(provider) ? (
            <ProviderTypeIcon key={provider} size={16} type={provider} />
          ) : (
            // Providers without a bespoke badge render their display name as
            // a tiny text pill (registry.dev "template" tag reference) instead
            // of the anonymous generic glyph.
            <Badge key={provider} size="sm" variant="tag">
              {getProviderDisplayName(provider)}
            </Badge>
          ),
        )}
      </span>
      {overflowCount > 0 && (
        <span aria-hidden className="text-text-neutral-secondary text-xs">
          +{overflowCount}
        </span>
      )}
    </span>
  );
}

interface RegistryOwnerAvatarProps {
  owner: RegistryArtifactOwner;
}

function RegistryOwnerAvatar({ owner }: RegistryOwnerAvatarProps) {
  // Owner logos come from short-lived signed URLs that can expire, so a
  // failed load falls back to the initial-letter avatar.
  const [logoFailed, setLogoFailed] = useState(false);

  if (owner.logoUrl && !logoFailed) {
    return (
      <img
        alt=""
        aria-hidden
        className="size-5 shrink-0 rounded-full object-cover"
        onError={() => setLogoFailed(true)}
        src={owner.logoUrl}
      />
    );
  }

  return (
    <span
      aria-hidden
      className="bg-bg-neutral-tertiary text-text-neutral-secondary flex size-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold uppercase"
    >
      {owner.name.charAt(0)}
    </span>
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
      {owner && (
        <span className="flex min-w-0 items-center gap-2">
          <RegistryOwnerAvatar owner={owner} />
          <span className="text-text-neutral-secondary truncate text-xs">
            {owner.name}
          </span>
        </span>
      )}
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

export function RegistryArtifactCard({
  artifact,
  isAddPending,
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
        <div className="flex items-center gap-3">
          {artifact.latestVersion && (
            <span className="text-text-neutral-secondary font-mono text-xs">
              v{artifact.latestVersion}
            </span>
          )}
          <span className="text-text-neutral-secondary flex items-center gap-1 text-xs">
            <Download aria-hidden className="size-3.5" />
            {artifact.totalDownloads}
          </span>
          <RegistryProviderCluster providers={artifact.providers} />
          <span className="ml-auto flex items-center gap-2">
            {artifact.isBuiltin && (
              <Badge aria-label="Built in" role="status" variant="tag">
                Built in
              </Badge>
            )}
            {artifact.isAdded ? (
              <>
                <Badge variant="outline">
                  <Check aria-hidden />
                  Added
                </Badge>
                <Button
                  aria-label={`Remove ${displayName}`}
                  onClick={(event) => onRemove(event.currentTarget)}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  Remove
                </Button>
              </>
            ) : (
              <Button
                aria-label={`Add ${displayName}`}
                disabled={isAddPending}
                onClick={onAdd}
                size="sm"
                type="button"
              >
                {isAddPending ? "Adding…" : "Add"}
              </Button>
            )}
          </span>
        </div>
      </div>
    </Card>
  );
}

interface RegistryTenantArtifactCardProps {
  normalizedName: string;
  onRemove: (trigger: HTMLButtonElement | null) => void;
  versionSpec: string;
}

export function RegistryTenantArtifactCard({
  normalizedName,
  onRemove,
  versionSpec,
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
          <p className="text-text-neutral-secondary truncate text-xs">
            Version {versionSpec}
          </p>
        </div>
      </div>
      <p className="text-text-neutral-secondary text-sm">
        Installed in this workspace. Catalog metadata is not available for this
        artifact.
      </p>
      <div className="mt-auto flex items-center">
        <span className="ml-auto">
          <Button
            aria-label={`Remove ${normalizedName}`}
            onClick={(event) => onRemove(event.currentTarget)}
            size="sm"
            type="button"
            variant="outline"
          >
            Remove
          </Button>
        </span>
      </div>
    </Card>
  );
}
