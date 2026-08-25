"use client";

import { BadgeCheck, Check, Download, ShieldCheck } from "lucide-react";
import { useRef } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import { getProviderDisplayName } from "@/types/providers";

import {
  REGISTRY_CAPABILITY_LABELS,
  type RegistryMarketplaceArtifact,
} from "./registry-explorer.model";

interface RegistryArtifactCardProps {
  artifact: RegistryMarketplaceArtifact;
  onOpen: (trigger: HTMLElement | null) => void;
}

function capabilitySummary(artifact: RegistryMarketplaceArtifact) {
  const labels = [
    artifact.hasProvider && REGISTRY_CAPABILITY_LABELS.provider,
    artifact.hasChecks && REGISTRY_CAPABILITY_LABELS.checks,
    artifact.hasCompliance && REGISTRY_CAPABILITY_LABELS.compliance,
  ].filter((label) => label !== false);
  return labels.join(", ");
}

export function RegistryArtifactCard({
  artifact,
  onOpen,
}: RegistryArtifactCardProps) {
  const nameButtonRef = useRef<HTMLButtonElement>(null);
  const displayName = artifact.name ?? artifact.normalizedName;
  const monogramSource = artifact.providers[0] ?? displayName;
  const subtitle = [
    artifact.providers.map(getProviderDisplayName).join(", "),
    capabilitySummary(artifact),
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    // Card onClick is a mouse-only enhancement; the keyboard path is the inner name button.
    <Card
      className="h-full gap-3"
      interactive
      onClick={() => onOpen(nameButtonRef.current)}
      padding="md"
      variant="inner"
    >
      <div className="flex items-start gap-3">
        <span
          aria-hidden
          className="bg-bg-neutral-tertiary text-text-neutral-secondary flex size-10 shrink-0 items-center justify-center rounded-lg text-sm font-semibold uppercase"
        >
          {monogramSource.slice(0, 2)}
        </span>
        <div className="min-w-0">
          <button
            className="text-text-neutral-primary block max-w-full truncate text-left text-sm font-semibold"
            onClick={(event) => {
              event.stopPropagation();
              onOpen(event.currentTarget);
            }}
            ref={nameButtonRef}
            type="button"
          >
            {displayName}
          </button>
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
      {(artifact.isOfficial || artifact.isVerified) && (
        <div className="flex flex-wrap gap-2">
          {artifact.isOfficial && (
            <Badge variant="tag">
              <ShieldCheck aria-hidden />
              Official
            </Badge>
          )}
          {artifact.isVerified && (
            <Badge variant="success">
              <BadgeCheck aria-hidden />
              Verified
            </Badge>
          )}
        </div>
      )}
      <div className="mt-auto flex items-center gap-3">
        {artifact.latestVersion && (
          <span className="text-text-neutral-secondary font-mono text-xs">
            v{artifact.latestVersion}
          </span>
        )}
        <span className="text-text-neutral-secondary flex items-center gap-1 text-xs">
          <Download aria-hidden className="size-3.5" />
          {artifact.totalDownloads}
        </span>
        <span className="ml-auto">
          {artifact.isAdded ? (
            <Badge variant="outline">
              <Check aria-hidden />
              Added
            </Badge>
          ) : (
            <Button
              aria-label={`Add ${displayName} from details`}
              onClick={(event) => {
                event.stopPropagation();
                onOpen(event.currentTarget);
              }}
              size="sm"
              type="button"
            >
              Add
            </Button>
          )}
        </span>
      </div>
    </Card>
  );
}

interface RegistryTenantArtifactCardProps {
  normalizedName: string;
  onOpen: (trigger: HTMLElement | null) => void;
  versionSpec: string;
}

export function RegistryTenantArtifactCard({
  normalizedName,
  onOpen,
  versionSpec,
}: RegistryTenantArtifactCardProps) {
  return (
    <Card className="h-full gap-3" padding="md" variant="inner">
      <div className="flex items-start gap-3">
        <span
          aria-hidden
          className="bg-bg-neutral-tertiary text-text-neutral-secondary flex size-10 shrink-0 items-center justify-center rounded-lg text-sm font-semibold uppercase"
        >
          {normalizedName.slice(0, 2)}
        </span>
        <div className="min-w-0">
          <button
            className="text-text-neutral-primary block max-w-full truncate text-left text-sm font-semibold"
            onClick={(event) => onOpen(event.currentTarget)}
            type="button"
          >
            {normalizedName}
          </button>
          <p className="text-text-neutral-secondary truncate text-xs">
            Version {versionSpec}
          </p>
        </div>
      </div>
      <p className="text-text-neutral-secondary text-sm">
        Installed in this workspace. Catalog metadata is not available for this
        artifact.
      </p>
    </Card>
  );
}
