import { Tooltip } from "@heroui/tooltip";
import React from "react";

import { IdIcon } from "@/components/icons";
import { ProviderType } from "@/types";

import { getProviderLogo } from "./get-provider-logo";
import { SnippetChip } from "./snippet-chip";

interface EntityInfoProps {
  cloudProvider: ProviderType;
  entityAlias?: string;
  entityId?: string;
  hideCopyButton?: boolean;
  snippetWidth?: string;
  showConnectionStatus?: boolean;
}

export const EntityInfoShort: React.FC<EntityInfoProps> = ({
  cloudProvider,
  entityAlias,
  entityId,
  hideCopyButton = false,
  showConnectionStatus = false,
}) => {
  return (
    <div className="flex items-center justify-start">
      <div className="flex items-center justify-between gap-x-2">
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
        <div className="flex max-w-[120px] flex-col gap-1">
          {entityAlias && (
            <Tooltip content={entityAlias} placement="top" size="sm">
              <span className="text-default-500 truncate text-xs text-ellipsis">
                {entityAlias}
              </span>
            </Tooltip>
          )}
          <SnippetChip
            value={entityId ?? ""}
            hideCopyButton={hideCopyButton}
            icon={<IdIcon className="size-4" />}
          />
        </div>
      </div>
    </div>
  );
};
