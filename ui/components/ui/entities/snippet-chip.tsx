import { Snippet } from "@heroui/snippet";
import { cn } from "@heroui/theme";
import { Tooltip } from "@heroui/tooltip";
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
      classNames={{
        content: "min-w-0 overflow-hidden",
        pre: "min-w-0 overflow-hidden text-ellipsis whitespace-nowrap",
        base: "border-border-neutral-tertiary bg-bg-neutral-tertiary rounded-lg border py-1",
      }}
      size="sm"
      hideSymbol
      copyIcon={<CopyIcon size={16} />}
      checkIcon={<DoneIcon size={16} />}
      hideCopyButton={hideCopyButton}
      codeString={value}
      {...props}
    >
      <div className="flex min-w-0 items-center gap-2" aria-label={ariaLabel}>
        {icon}
        <Tooltip content={value} placement="top" size="sm">
          <span className="min-w-0 flex-1 truncate text-xs">
            {formatter ? formatter(value) : value}
          </span>
        </Tooltip>
      </div>
    </Snippet>
  );
};
