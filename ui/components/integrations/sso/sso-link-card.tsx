"use client";

import { ShieldCheckIcon } from "lucide-react";

import { LinkCard } from "../shared/link-card";

export const SsoLinkCard = () => {
  return (
    <LinkCard
      icon={ShieldCheckIcon}
      title="SSO Configuration"
      description="Configure SAML Single Sign-On for your organization."
      learnMoreUrl="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-sso/"
      learnMoreAriaLabel="Learn more about SSO configuration"
      bodyText="SSO configuration is available in your User Profile. Enable SAML Single Sign-On to allow users to authenticate using your organization's identity provider."
      linkHref="/profile"
      linkText="Go to Profile"
    />
  );
};
