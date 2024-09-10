import { Snippet } from "@nextui-org/react";
import React from "react";

import { CopyIcon, DoneIcon, IdIcon } from "../icons";

interface SnippetIdProviderProps {
  providerId: string;
}
export const SnippetIdProvider: React.FC<SnippetIdProviderProps> = ({
  providerId,
}) => {
  return (
    <Snippet
      className="flex items-center py-0"
      size="sm"
      variant="flat"
      radius="lg"
      hideSymbol
      copyIcon={<CopyIcon size={16} />}
      checkIcon={<DoneIcon size={16} />}
    >
      <p className="flex items-center space-x-2">
        <IdIcon size={16} />
        <span className="text-sm max-w-24 overflow-x-scroll">{providerId}</span>
      </p>
    </Snippet>
  );
};
