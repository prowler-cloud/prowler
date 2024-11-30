import React from "react";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  KS8ProviderBadge,
} from "@/components/icons/providers-badge";

export type ProviderType = "aws" | "azure" | "gcp" | "kubernetes";

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
    default:
      return "Unknown Provider";
  }
};
