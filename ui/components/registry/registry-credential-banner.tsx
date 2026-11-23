import { ExternalLink, KeyRound } from "lucide-react";
import { type Ref } from "react";

import { Button } from "@/components/shadcn/button/button";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import {
  STATUS_PANEL_LAYOUT,
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
  /** The catalog works without a key; only entitled artifacts need one. */
  OPTIONAL_KEY: "optional_key",
  /** The catalog works without a key, and the stored one was rejected. */
  REJECTED_KEY: "rejected_key",
} as const;

type RegistryCredentialBannerVariant =
  (typeof REGISTRY_CREDENTIAL_BANNER)[keyof typeof REGISTRY_CREDENTIAL_BANNER];

const INLINE_KEY_COPY = {
  [REGISTRY_CREDENTIAL_BANNER.OPTIONAL_KEY]: {
    description:
      "Artifacts open to every workspace install without a key. Connect a Registry API key to add the ones that need approved access.",
    action: "Connect API key",
  },
  [REGISTRY_CREDENTIAL_BANNER.REJECTED_KEY]: {
    description:
      "The Registry rejected this workspace's API key. Replace it to add the artifacts that need approved access.",
    action: "Replace key",
  },
} as const;

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
  if (
    variant === REGISTRY_CREDENTIAL_BANNER.OPTIONAL_KEY ||
    variant === REGISTRY_CREDENTIAL_BANNER.REJECTED_KEY
  ) {
    const copy = INLINE_KEY_COPY[variant];
    return (
      <StatusPanel aria-live="polite" layout={STATUS_PANEL_LAYOUT.INLINE}>
        <StatusPanelIcon>
          <KeyRound />
        </StatusPanelIcon>
        <StatusPanelBody>
          <StatusPanelDescription>{copy.description}</StatusPanelDescription>
        </StatusPanelBody>
        <StatusPanelActions>
          {registryUrl && (
            <Button asChild size="sm" variant="ghost">
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
          <Button
            onClick={onConnect}
            ref={connectButtonRef}
            size="sm"
            type="button"
          >
            {copy.action}
          </Button>
        </StatusPanelActions>
      </StatusPanel>
    );
  }

  if (variant === REGISTRY_CREDENTIAL_BANNER.VALIDATING) {
    return (
      <StatusPanel aria-live="polite">
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
