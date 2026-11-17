import { ExternalLink, KeyRound } from "lucide-react";
import { type Ref } from "react";

import { Button } from "@/components/shadcn/button/button";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import {
  StatusPanel,
  StatusPanelActions,
  StatusPanelBody,
  StatusPanelDescription,
  StatusPanelIcon,
  StatusPanelTitle,
} from "@/components/shadcn/status-panel";

export const REGISTRY_CREDENTIAL_BANNER = {
  ONBOARDING: "onboarding",
  VALIDATING: "validating",
} as const;

type RegistryCredentialBannerVariant =
  (typeof REGISTRY_CREDENTIAL_BANNER)[keyof typeof REGISTRY_CREDENTIAL_BANNER];

interface RegistryCredentialBannerProps {
  variant: RegistryCredentialBannerVariant;
  connectButtonRef?: Ref<HTMLButtonElement>;
  onConnect: () => void;
  registryUrl?: string;
  /** Read only by the onboarding variant. */
  tenantArtifactCount?: number;
}

function installedArtifactsNote(count = 0) {
  if (count === 0) return "";
  return count === 1
    ? " The 1 artifact already in this workspace stays installed."
    : ` The ${count} artifacts already in this workspace stay installed.`;
}

export function RegistryCredentialBanner({
  variant,
  connectButtonRef,
  onConnect,
  registryUrl,
  tenantArtifactCount,
}: RegistryCredentialBannerProps) {
  if (variant === REGISTRY_CREDENTIAL_BANNER.VALIDATING) {
    return (
      <StatusPanel aria-busy aria-live="polite">
        <StatusPanelIcon>
          <Spinner />
        </StatusPanelIcon>
        <StatusPanelBody>
          <StatusPanelTitle>Validating your Registry API key</StatusPanelTitle>
          <StatusPanelDescription>
            The catalog opens after validation succeeds.
          </StatusPanelDescription>
        </StatusPanelBody>
        <StatusPanelActions>
          {/* Stays enabled while validation is pending: submitting a
              replacement key supersedes a validation that never settles. */}
          <Button
            onClick={onConnect}
            ref={connectButtonRef}
            type="button"
            variant="outline"
          >
            Use a different key
          </Button>
        </StatusPanelActions>
      </StatusPanel>
    );
  }

  return (
    <StatusPanel aria-live="polite">
      <StatusPanelIcon>
        <KeyRound />
      </StatusPanelIcon>
      <StatusPanelBody>
        <StatusPanelTitle>Connect your Registry API key</StatusPanelTitle>
        <StatusPanelDescription>
          A Registry API key is needed to add artifacts to this workspace.
          {installedArtifactsNote(tenantArtifactCount)}
        </StatusPanelDescription>
      </StatusPanelBody>
      <StatusPanelActions>
        <Button onClick={onConnect} ref={connectButtonRef} type="button">
          Connect API key
        </Button>
        {registryUrl && (
          <Button asChild variant="outline">
            <a
              aria-label="Explore Prowler Registry (opens in a new tab)"
              href={registryUrl}
              rel="noopener noreferrer"
              target="_blank"
            >
              Explore Prowler Registry
              <ExternalLink aria-hidden />
            </a>
          </Button>
        )}
      </StatusPanelActions>
    </StatusPanel>
  );
}
