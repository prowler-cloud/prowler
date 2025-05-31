import { cn, Snippet, Tooltip } from "@nextui-org/react";
import React from "react";

import { CopyIcon, DoneIcon } from "@/components/icons";

interface SnippetChipProps {
  value: string;
  ariaLabel?: string;
  icon?: React.ReactNode;
  hideCopyButton?: boolean;
  formatter?: (value: string) => string;
  className?: string;
}
export const SnippetChip = ({
  value,
  hideCopyButton = false,
  ariaLabel = `Copy ${value} to clipboard`,
  icon,
  formatter,
  className,
  ...props
}: SnippetChipProps) => {
  return (
    <Snippet
      className={cn("h-6", className)}
      color="default"
      size="sm"
      variant="flat"
      radius="lg"
      hideSymbol
      copyIcon={<CopyIcon size={16} />}
      checkIcon={<DoneIcon size={16} />}
      hideCopyButton={hideCopyButton}
      codeString={value}
      {...props}
    >
      <div className="flex items-center space-x-2" aria-label={ariaLabel}>
        {icon}
        <Tooltip content={value} placement="top" size="sm">
          <span className="no-scrollbar max-w-24 overflow-hidden overflow-x-scroll text-ellipsis whitespace-nowrap text-xs">
            {formatter ? formatter(value) : value}
          </span>
        </Tooltip>
      </div>
    </Snippet>
  );
};
