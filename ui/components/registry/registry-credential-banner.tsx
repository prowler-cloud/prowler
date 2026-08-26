import { KeyRound } from "lucide-react";
import { type Ref } from "react";

import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";

interface RegistryCredentialBannerProps {
  connectButtonRef?: Ref<HTMLButtonElement>;
  onConnect: () => void;
  tenantArtifactCount: number;
  validationPending: boolean;
}

export function RegistryCredentialBanner({
  connectButtonRef,
  onConnect,
  tenantArtifactCount,
  validationPending,
}: RegistryCredentialBannerProps) {
  const title = validationPending
    ? "Registry validation in progress"
    : "Connect your Registry API key";
  const copy = validationPending
    ? "Your Registry key is being validated. Catalog exploration will be available after validation succeeds."
    : "A Registry API key is required to install artifacts into this workspace.";

  return (
    <Card aria-live="polite" variant="base">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
        <span className="bg-bg-neutral-tertiary text-text-neutral-secondary flex size-10 shrink-0 items-center justify-center rounded-lg">
          <KeyRound aria-hidden className="size-5" />
        </span>
        <div className="space-y-2">
          <h2 className="text-base font-semibold">{title}</h2>
          <p className="text-text-neutral-secondary text-sm">{copy}</p>
          {tenantArtifactCount > 0 && (
            <p className="text-text-neutral-secondary text-sm">
              Your {tenantArtifactCount} preserved tenant artifact
              {tenantArtifactCount === 1 ? "" : "s"} will remain available in My
              artifacts.
            </p>
          )}
          <div className="flex flex-wrap gap-2 pt-2">
            {/* Stays enabled while validation is pending: submitting a
                replacement key supersedes a validation that never settles. */}
            <Button onClick={onConnect} ref={connectButtonRef} type="button">
              Connect API key
            </Button>
            <Button asChild variant="outline">
              <a
                aria-label="Explore Prowler Registry (opens in a new tab)"
                href="https://registry.prowler.com"
                rel="noopener noreferrer"
                target="_blank"
              >
                Explore Prowler Registry
              </a>
            </Button>
          </div>
        </div>
      </div>
    </Card>
  );
}
