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

import { REGISTRY_CAPABILITY_LABELS } from "./registry-explorer.model";

interface RegistryArtifactDetailCommonProps {
  catalogArtifact?: RegistryCatalogArtifact;
  headingRef?: Ref<HTMLHeadingElement>;
  isMutationPending: boolean;
  operationMessage?: string;
  tenantArtifact?: RegistryTenantArtifact;
}

type AddRegistryArtifactDetailProps = RegistryArtifactDetailCommonProps & {
  mode: "add";
  onAdd: (versionSpec?: string) => void;
  onRemove?: never;
  removeButtonRef?: never;
};

type RemoveRegistryArtifactDetailProps = RegistryArtifactDetailCommonProps & {
  mode: "remove";
  onAdd?: never;
  onRemove: () => void;
  removeButtonRef?: Ref<HTMLButtonElement>;
};

type RegistryArtifactDetailProps =
  | AddRegistryArtifactDetailProps
  | RemoveRegistryArtifactDetailProps;

export function RegistryArtifactDetail({
  catalogArtifact: artifact,
  headingRef,
  isMutationPending,
  mode,
  onAdd,
  onRemove,
  operationMessage,
  removeButtonRef,
  tenantArtifact,
}: RegistryArtifactDetailProps) {
  // Local state needed: the version pin is buffered until "Add to workspace" submits.
  const [usesExactVersion, setUsesExactVersion] = useState(false);
  const [exactVersion, setExactVersion] = useState("");
  const name = artifact?.name ?? tenantArtifact?.normalizedName;
  if (!name) return null;

  const badges: [boolean, string][] = artifact
    ? [
        [artifact.isOfficial, "Official"],
        [artifact.isVerified, "Verified"],
        [artifact.isMeta, "Meta"],
        [artifact.hasProvider, REGISTRY_CAPABILITY_LABELS.provider],
        [artifact.hasChecks, REGISTRY_CAPABILITY_LABELS.checks],
        [artifact.hasCompliance, REGISTRY_CAPABILITY_LABELS.compliance],
      ]
    : [];
  const metadata: [string, string][] = artifact
    ? [
        ["Latest version", artifact.latestVersion ?? "Not supplied"],
        ["Downloads", `${artifact.totalDownloads}`],
        ["Versions", `${artifact.versionCount}`],
        [
          "Owners",
          artifact.owners.length
            ? artifact.owners
                .map(({ name: ownerName, type }) => `${ownerName} (${type})`)
                .join(", ")
            : "Not supplied",
        ],
      ]
    : [];

  return (
    <section
      aria-labelledby="registry-artifact-title"
      className="flex min-h-0 flex-1 flex-col"
    >
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-6">
        <h2
          className="text-xl font-semibold"
          id="registry-artifact-title"
          ref={headingRef}
          tabIndex={-1}
        >
          {name}
        </h2>
        {badges.some(([visible]) => visible) && (
          <div className="flex flex-wrap gap-2">
            {badges.map(([visible, label]) =>
              visible ? (
                <Badge key={label} variant="outline">
                  {label}
                </Badge>
              ) : null,
            )}
          </div>
        )}
        {artifact?.description && (
          <p className="text-text-neutral-secondary text-sm">
            {artifact.description}
          </p>
        )}
        {artifact && (
          <>
            <p className="text-sm">
              Providers:{" "}
              {artifact.providers.map(getProviderDisplayName).join(", ")}
            </p>
            <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {metadata.map(([label, value]) => (
                <div
                  className="border-border-neutral-tertiary bg-bg-neutral-tertiary rounded-lg border px-3 py-2"
                  key={label}
                >
                  <dt className="text-text-neutral-secondary text-xs">
                    {label}
                  </dt>
                  <dd className="text-sm font-medium">{value}</dd>
                </div>
              ))}
            </dl>
          </>
        )}
        {tenantArtifact && (
          <p className="text-sm">
            My version specification: {tenantArtifact.versionSpec}
          </p>
        )}
      </div>
      <div className="border-border-neutral-secondary bg-bg-neutral-secondary sticky bottom-0 space-y-4 border-t p-6">
        {operationMessage && <p role="alert">{operationMessage}</p>}
        {mode === "remove" ? (
          <Button
            onClick={onRemove}
            ref={removeButtonRef}
            type="button"
            variant="destructive"
          >
            Remove
          </Button>
        ) : (
          <>
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
            <Button
              className="w-full"
              disabled={
                isMutationPending ||
                (usesExactVersion && exactVersion.trim().length === 0)
              }
              onClick={() =>
                onAdd(usesExactVersion ? exactVersion.trim() : undefined)
              }
              type="button"
            >
              {isMutationPending ? "Adding artifact" : "Add to workspace"}
            </Button>
          </>
        )}
      </div>
    </section>
  );
}
