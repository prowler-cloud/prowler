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

export const getProviderVideoLink = (providerType: ProviderType) => {
  switch (providerType) {
    case "aws":
      return {
        text: "How to setup an AWS account?",
        link: "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/#step-41-aws-credentials",
      };
    case "azure":
      return {
        text: "How to setup an Azure subscription?",
        link: "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/#step-42-azure-credentials",
      };
    case "gcp":
      return {
        text: "How to setup a GCP project?",
        link: "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/#step-43-gcp-credentials",
      };
    case "kubernetes":
      return {
        text: "How to setup a Kubernetes cluster?",
        link: "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/#step-44-kubernetes-credentials",
      };
    default:
      return {
        text: "How to setup a provider?",
        link: "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/#step-3-add-a-provider",
      };
  }
};
