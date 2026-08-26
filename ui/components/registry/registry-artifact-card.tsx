"use client";

import { BadgeCheck, Check, Download, ShieldCheck } from "lucide-react";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import { getProviderDisplayName } from "@/types/providers";
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
          {owner.logoUrl ? (
            <img
              alt=""
              aria-hidden
              className="size-5 shrink-0 rounded-full object-cover"
              src={owner.logoUrl}
            />
          ) : (
            <span
              aria-hidden
              className="bg-bg-neutral-tertiary text-text-neutral-secondary flex size-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold uppercase"
            >
              {owner.name.charAt(0)}
            </span>
          )}
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
  // Unknown or absent providers fall back to the generic provider badge
  // rendered by ProviderTypeIcon itself.
  const primaryProvider = artifact.providers[0] ?? "";
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
          className="bg-bg-neutral-tertiary flex size-10 shrink-0 items-center justify-center overflow-hidden rounded-lg"
        >
          <ProviderTypeIcon size={26} type={primaryProvider} />
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
          <span className="ml-auto flex items-center gap-2">
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
          className="bg-bg-neutral-tertiary flex size-10 shrink-0 items-center justify-center overflow-hidden rounded-lg"
        >
          {/* Tenant artifacts carry no provider metadata, so the icon renders
              its own generic provider fallback. */}
          <ProviderTypeIcon size={26} type="" />
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
