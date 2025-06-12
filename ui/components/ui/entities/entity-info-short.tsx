import { Tooltip } from "@nextui-org/react";
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
}

export const EntityInfoShort: React.FC<EntityInfoProps> = ({
  cloudProvider,
  entityAlias,
  entityId,
  hideCopyButton = false,
}) => {
  return (
    <div className="flex items-center justify-start">
      <div className="flex items-center justify-between gap-x-2">
        <div className="flex-shrink-0">{getProviderLogo(cloudProvider)}</div>
        <div className="flex max-w-[120px] flex-col">
          {entityAlias && (
            <Tooltip content={entityAlias} placement="top" size="sm">
              <span className="truncate text-ellipsis text-xs text-default-500">
                {entityAlias}
              </span>
            </Tooltip>
          )}
          <SnippetChip
            value={entityId ?? ""}
            hideCopyButton={hideCopyButton}
            icon={<IdIcon size={16} />}
          />
        </div>
      </div>
    </div>
  );
};
