import React from "react";

import { getProviderLogo } from "./get-provider-logo";
import { SnippetId } from "./snippet-id";
import { SnippetLabel } from "./snippet-label";

interface EntityInfoProps {
  cloudProvider: "aws" | "azure" | "gcp" | "kubernetes";
  entityAlias?: string;
  entityId?: string;
}

export const EntityInfoShort: React.FC<EntityInfoProps> = ({
  cloudProvider,
  entityAlias,
  entityId,
}) => {
  return (
    <div className="flex w-full items-center justify-between space-x-4">
      <div className="flex items-center gap-x-4">
        <div className="flex-shrink-0">{getProviderLogo(cloudProvider)}</div>
        <div className="flex flex-col">
          <SnippetLabel label={entityAlias ?? ""} />
          <SnippetId entityId={entityId ?? ""} />
        </div>
      </div>
    </div>
  );
};
