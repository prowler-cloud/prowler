import { Snippet, Tooltip } from "@nextui-org/react";
import React from "react";

import { CopyIcon, DoneIcon, IdIcon } from "@/components/icons";

interface SnippetIdProps {
  entityId: string;
  hideCopyButton?: boolean;
  [key: string]: any;
}
export const SnippetId: React.FC<SnippetIdProps> = ({
  entityId,
  hideCopyButton = false,
  ...props
}) => {
  return (
    <Snippet
      className="flex h-6 items-center py-0"
      color="default"
      size="sm"
      variant="flat"
      radius="lg"
      hideSymbol
      copyIcon={<CopyIcon size={16} />}
      checkIcon={<DoneIcon size={16} />}
      hideCopyButton={hideCopyButton}
      {...props}
    >
      <p className="flex items-center space-x-2">
        <IdIcon size={18} />
        <Tooltip content={entityId} placement="top">
          <span className="no-scrollbar w-24 overflow-hidden overflow-x-scroll text-ellipsis whitespace-nowrap text-xs">
            {entityId}
          </span>
        </Tooltip>
      </p>
    </Snippet>
  );
};
