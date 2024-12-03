import { Snippet } from "@nextui-org/react";
import React from "react";

import { CopyIcon, DoneIcon, IdIcon } from "@/components/icons";

interface SnippetIdProps {
  entityId: string;
  [key: string]: any;
}
export const SnippetId: React.FC<SnippetIdProps> = ({ entityId, ...props }) => {
  return (
    <Snippet
      className="flex h-4 items-center py-0"
      color="default"
      size="sm"
      variant="flat"
      radius="lg"
      hideSymbol
      copyIcon={<CopyIcon size={16} />}
      checkIcon={<DoneIcon size={16} />}
      {...props}
    >
      <p className="flex items-center space-x-2">
        <IdIcon size={18} />
        <span className="no-scrollbar w-14 overflow-hidden overflow-x-scroll text-ellipsis whitespace-nowrap text-xs">
          {entityId}
        </span>
      </p>
    </Snippet>
  );
};
