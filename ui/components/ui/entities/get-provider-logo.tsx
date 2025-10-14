import React from "react";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
} from "@/components/icons/providers-badge";
import { ProviderType } from "@/types";

export const getProviderLogo = (provider: ProviderType) => {
  switch (provider) {
    case "aws":
      return <AWSProviderBadge width={35} height={35} />;
    case "azure":
      return <AzureProviderBadge width={35} height={35} />;
    case "gcp":
      return <GCPProviderBadge width={35} height={35} />;
    case "kubernetes":
      return <KS8ProviderBadge width={35} height={35} />;
    case "m365":
      return <M365ProviderBadge width={35} height={35} />;
    case "github":
      return <GitHubProviderBadge width={35} height={35} />;
    default:
      return null;
  }
};

export const getProviderName = (provider: ProviderType): string => {
  switch (provider) {
    case "aws":
      return "Amazon Web Services";
    case "azure":
      return "Microsoft Azure";
    case "gcp":
      return "Google Cloud Platform";
    case "kubernetes":
      return "Kubernetes";
    case "m365":
      return "Microsoft 365";
    case "github":
      return "GitHub";
    default:
      return "Unknown Provider";
  }
};
