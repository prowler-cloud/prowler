"use client";

import {
  BadgeCheck,
  Check,
  ExternalLink,
  Package,
  ShieldCheck,
} from "lucide-react";
import type { ReactNode } from "react";

import { ProviderTypeIconStack } from "@/components/icons/providers-badge/provider-type-icon";
import { ProwlerShort } from "@/components/icons/prowler/ProwlerIcons";
import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/shadcn/avatar/avatar";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import {
  getRegistryNotInstallableMessage,
  REGISTRY_NOT_INSTALLABLE_REASON,
} from "@/lib/registry/installability";
import { cn } from "@/lib/utils";
import { getProviderDisplayName, isKnownProviderType } from "@/types/providers";
import type { RegistryArtifactOwner } from "@/types/registry";

import {
  REGISTRY_CAPABILITY_LABELS,
  type RegistryMarketplaceArtifact,
} from "./registry-explorer.model";

const MAX_PROVIDER_ICONS = 4;
// Names are wider than logos, so fewer fit on one line.
const MAX_PROVIDER_NAMES = 3;

const PROVIDER_LIST_FORMAT = new Intl.ListFormat("en", {
  style: "long",
  type: "conjunction",
});

// Package names compare case-insensitively, with runs of -_. as one "-".
function normalizePackageName(value: string) {
  return value.toLowerCase().replace(/[-_.]+/g, "-");
}

interface RegistryArtifactHeaderProps {
  title: string;
  /** Monospace when the title is the package id, not a display name. */
  isPackageId: boolean;
  byline: ReactNode;
}

function RegistryArtifactHeader({
  title,
  isPackageId,
  byline,
}: RegistryArtifactHeaderProps) {
  return (
    <div className="flex items-start gap-3">
      <span
        aria-hidden
        className="bg-bg-neutral-tertiary text-text-neutral-secondary flex size-10 shrink-0 items-center justify-center overflow-hidden rounded-lg"
      >
        {/* Artifacts can span several providers, so the header shows a
            neutral package mark instead of any single provider logo. */}
        <Package size={26} />
      </span>
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <h3
          className={cn(
            "text-text-neutral-primary truncate text-sm font-semibold",
            isPackageId && "font-mono",
          )}
        >
          {title}
        </h3>
        <div className="flex min-h-5 min-w-0 flex-wrap items-center gap-2">
          {byline}
        </div>
      </div>
    </div>
  );
}

interface RegistryArtifactBylineProps {
  isOfficial: boolean;
  isVerified: boolean;
  owner?: RegistryArtifactOwner;
}

function RegistryArtifactByline({
  isOfficial,
  isVerified,
  owner,
}: RegistryArtifactBylineProps) {
  return (
    <>
      {owner &&
        (owner.name.trim().toLowerCase() === "prowler" ? (
          <ProwlerShort aria-label="Prowler" role="img" size={20} />
        ) : (
          <span className="flex min-w-0 items-center gap-1.5">
            <Avatar aria-hidden className="size-5">
              <AvatarImage alt="" src={owner.logoUrl} />
              <AvatarFallback>{owner.name.charAt(0)}</AvatarFallback>
            </Avatar>
            <span className="text-text-neutral-secondary truncate text-xs">
              {owner.name}
            </span>
          </span>
        ))}
      {/* Official already implies verified: one trust mark per card. */}
      {isOfficial ? (
        <Badge size="sm" variant="tag">
          <ShieldCheck aria-hidden />
          Official
        </Badge>
      ) : isVerified ? (
        <Badge size="sm" variant="success">
          <BadgeCheck aria-hidden />
          Verified
        </Badge>
      ) : null}
    </>
  );
}

function countChip(
  count: number | undefined,
  singular: string,
  plural: string,
  bare: string,
): ReactNode {
  if (typeof count !== "number") return bare;
  return (
    <>
      <span className="font-semibold tabular-nums">
        {count.toLocaleString("en-US")}
      </span>{" "}
      {count === 1 ? singular : plural}
    </>
  );
}

// One chip per capability the artifact has; null counts stay unknown.
function RegistryArtifactChips({
  artifact,
}: {
  artifact: RegistryMarketplaceArtifact;
}) {
  const chips = [
    artifact.hasProvider && {
      key: "provider",
      content: REGISTRY_CAPABILITY_LABELS.provider,
    },
    artifact.hasChecks && {
      key: "checks",
      content: countChip(
        artifact.checkCount,
        "check",
        "checks",
        REGISTRY_CAPABILITY_LABELS.checks,
      ),
    },
    artifact.hasCompliance && {
      key: "compliance",
      content: countChip(
        artifact.complianceCount,
        "compliance framework",
        "compliance frameworks",
        REGISTRY_CAPABILITY_LABELS.compliance,
      ),
    },
  ].filter((chip) => chip !== false);

  if (chips.length === 0) return null;

  return (
    <ul aria-label="Contents" className="flex flex-wrap gap-1.5">
      {chips.map((chip) => (
        <li key={chip.key} className="max-w-full">
          <Badge variant="tag">{chip.content}</Badge>
        </li>
      ))}
    </ul>
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

interface RegistryProviderNamesProps {
  providers: string[];
}

/** Providers without a logo, capped like the logo stack with the rest behind +N. */
function RegistryProviderNames({ providers }: RegistryProviderNamesProps) {
  if (providers.length === 0) return null;
  const visible = providers.slice(0, MAX_PROVIDER_NAMES);
  const overflow = providers.slice(MAX_PROVIDER_NAMES);
  const overflowLabel = overflow.map(getProviderDisplayName).join(", ");

  return (
    <ul
      aria-label="Providers"
      className="text-text-neutral-secondary flex flex-wrap items-center gap-x-1 text-xs"
    >
      {visible.map((provider, index) => (
        <li
          key={provider}
          className={cn(index < visible.length - 1 && "after:content-[',']")}
        >
          {getProviderDisplayName(provider)}
        </li>
      ))}
      {overflow.length > 0 && (
        <li>
          <Tooltip delayDuration={150}>
            <TooltipTrigger asChild>
              <span
                aria-label={`${overflow.length} more: ${overflowLabel}`}
                className="focus-visible:outline-button-primary rounded-sm font-medium focus-visible:outline-2 focus-visible:outline-offset-2"
                role="img"
                tabIndex={0}
              >
                +{overflow.length}
              </span>
            </TooltipTrigger>
            <TooltipContent className="max-w-xs" side="top">
              {overflowLabel}
            </TooltipContent>
          </Tooltip>
        </li>
      )}
    </ul>
  );
}

interface RegistryArtifactFactsProps {
  version: string;
  /** Set when an update is available; `version` is then the installed one. */
  availableVersion?: string;
  versionLabel: string;
  downloads?: number;
}

function RegistryArtifactFacts({
  version,
  availableVersion,
  versionLabel,
  downloads,
}: RegistryArtifactFactsProps) {
  if (!version && downloads === undefined) return null;

  return (
    <dl
      role="group"
      aria-label="Artifact metadata"
      className="text-text-neutral-secondary flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-xs"
    >
      {version && (
        <div className="flex min-w-0 flex-wrap items-center gap-x-1">
          <dt className="sr-only">
            {availableVersion ? "Installed" : versionLabel}
          </dt>
          <dd className="text-text-neutral-primary font-mono wrap-anywhere">
            {version}
          </dd>
          {availableVersion && (
            <>
              <dt className="sr-only">Available</dt>
              <dd className="text-text-neutral-primary font-mono wrap-anywhere">
                <span aria-hidden className="text-text-neutral-secondary">
                  →{" "}
                </span>
                {availableVersion}
              </dd>
            </>
          )}
        </div>
      )}
      {downloads !== undefined && (
        <div className="min-w-0">
          <dt className="sr-only">Downloads</dt>
          <dd className="wrap-anywhere">
            <span className="text-text-neutral-primary font-semibold tabular-nums">
              {downloads.toLocaleString("en-US")}
            </span>{" "}
            {downloads === 1 ? "download" : "downloads"}
          </dd>
        </div>
      )}
    </dl>
  );
}

interface RegistryArtifactCardProps {
  artifact: RegistryMarketplaceArtifact;
  pendingAddName?: string;
  /** Base for the Registry page where access is requested. */
  registryUrl?: string;
  onAdd: () => void;
  onRemove: (trigger: HTMLButtonElement | null) => void;
}

export function RegistryArtifactCard({
  artifact,
  pendingAddName,
  registryUrl,
  onAdd,
  onRemove,
}: RegistryArtifactCardProps) {
  const displayName = artifact.name ?? artifact.normalizedName;
  const logoProviders = artifact.providers.filter(isKnownProviderType);
  const namedProviders = artifact.providers.filter(
    (provider) => !isKnownProviderType(provider),
  );
  const accessRequestUrl =
    artifact.notInstallableReason ===
      REGISTRY_NOT_INSTALLABLE_REASON.ACCESS_REQUIRED &&
    registryUrl &&
    artifact.accessRequestPath
      ? new URL(artifact.accessRequestPath, registryUrl).href
      : undefined;
  const isPackageId =
    !artifact.name ||
    normalizePackageName(artifact.name) ===
      normalizePackageName(artifact.normalizedName);
  const note = artifact.isAdded ? (
    <RegistryExtendedProviders slugs={artifact.extendsProviderSlugs} />
  ) : !artifact.isInstallable && !artifact.isBuiltin ? (
    <p className="text-text-neutral-secondary text-xs">
      {getRegistryNotInstallableMessage(artifact.notInstallableReason)}
    </p>
  ) : null;

  return (
    <Card className="h-full gap-3" padding="md" variant="inner">
      <RegistryArtifactHeader
        title={displayName}
        isPackageId={isPackageId}
        byline={
          <RegistryArtifactByline
            isOfficial={artifact.isOfficial}
            isVerified={artifact.isVerified}
            owner={artifact.owners[0]}
          />
        }
      />
      {artifact.description && (
        <p className="text-text-neutral-secondary line-clamp-2 text-sm">
          {artifact.description}
        </p>
      )}
      <RegistryArtifactChips artifact={artifact} />
      {note}
      {/* Kept out of the footer so it stays one line and footers line up. */}
      <RegistryProviderNames providers={namedProviders} />
      <div className="border-border-neutral-tertiary mt-auto flex flex-wrap items-center gap-x-3 gap-y-2 border-t pt-3">
        {logoProviders.length > 0 && (
          <ProviderTypeIconStack
            focusable
            max={MAX_PROVIDER_ICONS}
            size={16}
            items={logoProviders.map((provider) => ({
              key: provider,
              type: provider,
              tooltip: getProviderDisplayName(provider),
            }))}
          />
        )}
        <RegistryArtifactFacts
          version={
            artifact.isAdded
              ? artifact.resolvedVersion || "Unknown"
              : (artifact.latestVersion ?? "")
          }
          availableVersion={
            artifact.updateAvailable ? artifact.latestVersion : undefined
          }
          versionLabel={artifact.isAdded ? "Installed" : "Version"}
          downloads={artifact.isBuiltin ? undefined : artifact.totalDownloads}
        />
        <div className="ml-auto flex min-h-8 shrink-0 items-center gap-2">
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
                variant="ghost"
              >
                Remove
              </Button>
            </>
          ) : accessRequestUrl ? (
            <Button asChild size="sm" variant="outline">
              <a
                aria-label={`Request access to ${displayName} in the Prowler Registry (opens in a new tab)`}
                href={accessRequestUrl}
                rel="noopener noreferrer"
                target="_blank"
              >
                Request access
                <ExternalLink aria-hidden />
              </a>
            </Button>
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
          ) : artifact.isBuiltin ? (
            <span className="text-text-neutral-secondary text-xs">
              Included in Prowler
            </span>
          ) : null}
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
      <RegistryArtifactHeader
        title={normalizedName}
        isPackageId
        byline={
          <span className="text-text-neutral-secondary text-xs">
            Installed in this workspace
          </span>
        }
      />
      <p className="text-text-neutral-secondary text-sm">
        Catalog details are not available for this artifact.
      </p>
      <RegistryExtendedProviders slugs={extendsProviderSlugs} />
      <div className="border-border-neutral-tertiary mt-auto flex flex-wrap items-center gap-x-3 gap-y-2 border-t pt-3">
        <RegistryArtifactFacts
          version={resolvedVersion || "Unknown"}
          versionLabel="Installed"
        />
        <div className="ml-auto flex min-h-8 shrink-0 items-center gap-2">
          <Button
            aria-label={`Remove ${normalizedName}`}
            onClick={(event) => onRemove(event.currentTarget)}
            size="sm"
            type="button"
            variant="ghost"
          >
            Remove
          </Button>
        </div>
      </div>
    </Card>
  );
}
