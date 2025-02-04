import { Snippet } from "@nextui-org/react";
import React from "react";

import { CopyIcon, DoneIcon } from "@/components/icons";

interface SnippetLabelProps {
  label: string;
  [key: string]: any;
}
export const SnippetLabel: React.FC<SnippetLabelProps> = ({
  label,
  ...props
}) => {
  return (
    label !== "" && (
      <Snippet
        className="m-0 flex items-center bg-transparent py-0"
        color="default"
        size="sm"
        radius="lg"
        hideSymbol
        copyIcon={<CopyIcon size={16} />}
        checkIcon={<DoneIcon size={16} />}
        {...props}
      >
        <p className="no-scrollbar text-md mb-1 w-32 overflow-hidden overflow-x-scroll text-ellipsis whitespace-nowrap text-sm font-semibold">
          {label}
        </p>
      </Snippet>
    )
  );
};
