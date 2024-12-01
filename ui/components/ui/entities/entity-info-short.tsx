import React from "react";

import { getProviderLogo } from "./get-provider-logo";
import { SnippetId } from "./snippet-id";

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
    <div className="flex w-full items-center justify-between space-x-2">
      <div className="flex items-center gap-x-2">
        <div className="flex-shrink-0">{getProviderLogo(cloudProvider)}</div>
        <div className="flex flex-col space-y-1">
          {entityAlias && (
            <span className="text-tiny text-default-500">{entityAlias}</span>
          )}
          <SnippetId entityId={entityId ?? ""} />
        </div>
      </div>
    </div>
  );
};
