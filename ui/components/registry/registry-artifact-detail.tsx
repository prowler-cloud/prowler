"use client";

import { type Ref, useState } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Checkbox } from "@/components/shadcn/checkbox";
import { Input } from "@/components/shadcn/input/input";
import { getProviderDisplayName } from "@/types/providers";
import type {
  RegistryCatalogArtifact,
  RegistryTenantArtifact,
} from "@/types/registry";

interface RegistryArtifactDetailProps {
  catalogArtifact?: RegistryCatalogArtifact;
  headingRef?: Ref<HTMLHeadingElement>;
  removeButtonRef?: Ref<HTMLButtonElement>;
  tenantArtifact?: RegistryTenantArtifact;
  isMutationPending?: boolean;
  onAdd?: (versionSpec?: string) => void;
  onRemove?: () => void;
}

export function RegistryArtifactDetail({
  catalogArtifact: artifact,
  headingRef,
  removeButtonRef,
  tenantArtifact,
  isMutationPending = false,
  onAdd,
  onRemove,
}: RegistryArtifactDetailProps) {
  const [isAddFormOpen, setIsAddFormOpen] = useState(false);
  const [usesExactVersion, setUsesExactVersion] = useState(false);
  const [exactVersion, setExactVersion] = useState("");
  const name = artifact?.name ?? tenantArtifact?.normalizedName;
  if (!name) return null;

  const badges: [boolean, string][] = artifact
    ? [
        [artifact.isOfficial, "Official"],
        [artifact.isVerified, "Verified"],
        [artifact.isMeta, "Meta"],
        [artifact.hasProvider, "Provider"],
        [artifact.hasChecks, "Checks"],
        [artifact.hasCompliance, "Compliance"],
      ]
    : [];
  const metadata = artifact
    ? [
        `Providers: ${artifact.providers.map(getProviderDisplayName).join(", ")}`,
        `Latest version: ${artifact.latestVersion ?? "Not supplied"}`,
        `Versions: ${artifact.versionCount}`,
        `Downloads: ${artifact.totalDownloads}`,
        `Owners: ${artifact.owners.length ? artifact.owners.map(({ name: ownerName, type }) => `${ownerName} (${type})`).join(", ") : "Not supplied"}`,
      ]
    : [];

  return (
    <section aria-labelledby="registry-artifact-title">
      <h1
        className="text-xl font-semibold"
        id="registry-artifact-title"
        ref={headingRef}
        tabIndex={-1}
      >
        {name}
      </h1>
      {artifact?.description && (
        <p className="text-text-neutral-secondary mt-2 text-sm">
          {artifact.description}
        </p>
      )}
      <div className="mt-4 flex flex-wrap gap-2">
        {badges.map(([visible, label]) =>
          visible ? (
            <Badge key={label} variant="outline">
              {label}
            </Badge>
          ) : null,
        )}
      </div>
      <div className="mt-6 space-y-3 text-sm">
        {metadata.map((value) => (
          <p key={value}>{value}</p>
        ))}
        {tenantArtifact && (
          <p>My version specification: {tenantArtifact.versionSpec}</p>
        )}
      </div>
      {tenantArtifact ? (
        <Button
          className="mt-6"
          onClick={onRemove}
          ref={removeButtonRef}
          type="button"
          variant="destructive"
        >
          Remove
        </Button>
      ) : artifact ? (
        isAddFormOpen ? (
          <div className="mt-6 space-y-4">
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={usesExactVersion}
                id="registry-exact-version"
                onCheckedChange={(checked) =>
                  setUsesExactVersion(checked === true)
                }
              />
              Use an exact version
            </label>
            {usesExactVersion && (
              <Input
                aria-label="Exact version pin"
                onChange={(event) => setExactVersion(event.target.value)}
                placeholder="1.2.3"
                value={exactVersion}
              />
            )}
            <div className="flex flex-wrap gap-2">
              <Button
                disabled={
                  isMutationPending ||
                  (usesExactVersion && exactVersion.trim().length === 0)
                }
                onClick={() =>
                  onAdd?.(usesExactVersion ? exactVersion.trim() : undefined)
                }
                type="button"
              >
                {isMutationPending ? "Adding artifact" : "Add artifact"}
              </Button>
              <Button
                disabled={isMutationPending}
                onClick={() => setIsAddFormOpen(false)}
                type="button"
                variant="outline"
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <Button onClick={() => setIsAddFormOpen(true)} type="button">
            Add
          </Button>
        )
      ) : null}
    </section>
  );
}
