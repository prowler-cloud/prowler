import { Snippet } from "@nextui-org/react";
import React from "react";

import { CopyIcon, DoneIcon, IdIcon } from "../icons";

interface SnippetIdProviderProps {
  providerId: string;
  [key: string]: any;
}
export const SnippetIdProvider: React.FC<SnippetIdProviderProps> = ({
  providerId,
  ...props
}) => {
  return (
    <Snippet
      className="flex items-center py-0"
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
        <IdIcon size={16} />
        <span className="no-scrollbar max-w-24 overflow-x-scroll text-sm">
          {providerId}
        </span>
      </p>
    </Snippet>
  );
};
