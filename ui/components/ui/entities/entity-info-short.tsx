import React from "react";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  KS8ProviderBadge,
} from "../../icons/providers-badge";
import { SnippetId } from "./snippet-id";
import { SnippetLabel } from "./snippet-label";

interface EntityInfoProps {
  connected?: boolean | null;
  cloudProvider?: "aws" | "azure" | "gcp" | "kubernetes";
  entityAlias?: string;
  entityId?: string;
}

export const EntityInfoShort: React.FC<EntityInfoProps> = ({
  cloudProvider,
  entityAlias,
  entityId,
}) => {
  const getProviderLogo = () => {
    switch (cloudProvider) {
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

  return (
    <div className="flex w-full items-center justify-between space-x-4">
      <div className="flex items-center gap-x-4">
        <div className="flex-shrink-0">{getProviderLogo()}</div>
        <div className="flex flex-col">
          <SnippetLabel label={entityAlias ?? ""} />
          <SnippetId entityId={entityId ?? ""} />
        </div>
      </div>
    </div>
  );
};
