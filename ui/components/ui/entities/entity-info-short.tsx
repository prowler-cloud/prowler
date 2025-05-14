import React from "react";

import { ProviderType } from "@/types";

import { getProviderLogo } from "./get-provider-logo";
import { SnippetId } from "./snippet-id";

interface EntityInfoProps {
  cloudProvider: ProviderType;
  entityAlias?: string;
  entityId?: string;
  hideCopyButton?: boolean;
}

export const EntityInfoShort: React.FC<EntityInfoProps> = ({
  cloudProvider,
  entityAlias,
  entityId,
  hideCopyButton = false,
}) => {
  return (
    <div className="flex w-full items-center justify-between space-x-2">
      <div className="flex items-center gap-x-2">
        <div className="flex-shrink-0">{getProviderLogo(cloudProvider)}</div>
        <div className="flex flex-col">
          {entityAlias && (
            <span className="text-xs text-default-500">{entityAlias}</span>
          )}
          <SnippetId
            entityId={entityId ?? ""}
            hideCopyButton={hideCopyButton}
          />
        </div>
      </div>
    </div>
  );
};
