import { Tooltip } from "@heroui/tooltip";
import React from "react";

import { ProviderType } from "@/types";

import { getProviderLogo } from "./get-provider-logo";

interface EntityInfoProps {
  cloudProvider: ProviderType;
  entityAlias?: string;
  entityId?: string;
  snippetWidth?: string;
  showConnectionStatus?: boolean;
  maxWidth?: string;
}

export const EntityInfo: React.FC<EntityInfoProps> = ({
  cloudProvider,
  entityAlias,
  entityId,
  showConnectionStatus = false,
  maxWidth = "w-[120px]",
}) => {
  return (
    <div className="flex items-center gap-2">
      <div className="relative shrink-0">
        {getProviderLogo(cloudProvider)}
        {showConnectionStatus && (
          <Tooltip
            size="sm"
            content={showConnectionStatus ? "Connected" : "Not Connected"}
          >
            <span
              className={`absolute top-[-0.1rem] right-[-0.2rem] h-2 w-2 cursor-pointer rounded-full ${
                showConnectionStatus ? "bg-green-500" : "bg-red-500"
              }`}
            />
          </Tooltip>
        )}
      </div>
      <div className={`flex ${maxWidth} flex-col gap-1`}>
        {entityAlias ? (
          <Tooltip content={entityAlias} placement="top-start" size="sm">
            <p className="text-text-neutral-primary truncate text-left text-xs font-medium">
              {entityAlias}
            </p>
          </Tooltip>
        ) : (
          <Tooltip content="No alias" placement="top-start" size="sm">
            <p className="text-text-neutral-secondary truncate text-left text-xs">
              -
            </p>
          </Tooltip>
        )}
        {entityId && (
          <Tooltip content={entityId} placement="top-start" size="sm">
            <p className="text-text-neutral-secondary truncate text-left text-xs">
              ID: {entityId}
            </p>
          </Tooltip>
        )}
      </div>
    </div>
  );
};
