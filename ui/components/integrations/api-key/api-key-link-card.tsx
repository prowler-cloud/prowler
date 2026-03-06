"use client";

import { KeyRoundIcon } from "lucide-react";

import { LinkCard } from "../shared/link-card";

export const ApiKeyLinkCard = () => {
  return (
    <LinkCard
      icon={KeyRoundIcon}
      title="API Keys"
      description="Manage API keys for programmatic access."
      learnMoreUrl="https://docs.prowler.com/user-guide/tutorials/prowler-app-api-keys"
      learnMoreAriaLabel="Learn more about API Keys"
      bodyText="API Key management is available in your User Profile. Create and manage API keys to authenticate with the Prowler API for automation and integrations."
      linkHref="/profile"
      linkText="Go to Profile"
    />
  );
};
