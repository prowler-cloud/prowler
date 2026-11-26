"use client";

import { KeyRoundIcon } from "lucide-react";

import { PremiumBadge } from "@/components/shared/premium-badge";
import { isCloud } from "@/lib/shared/env";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { LinkCard } from "../shared/link-card";

export const ApiKeyLinkCard = () => {
  const isLocalServer = !isCloud();

  return (
    <LinkCard
      icon={KeyRoundIcon}
      title="API Keys"
      titleBadge={
        isLocalServer ? (
          <PremiumBadge feature={CLOUD_UPGRADE_FEATURE.API_KEYS} compact />
        ) : undefined
      }
      description="Manage API keys for programmatic access."
      learnMoreUrl="https://docs.prowler.com/user-guide/tutorials/prowler-app-api-keys"
      learnMoreAriaLabel="Learn more about API Keys"
      bodyText={
        isLocalServer
          ? "API keys are available in Prowler Cloud and Private Cloud. Your User Profile shows what they unlock for automation and integrations."
          : "API Key management is available in your User Profile. Create and manage API keys to authenticate with the Prowler API for automation and integrations."
      }
      linkHref="/profile#api-keys"
      linkText="Go to Profile"
    />
  );
};
