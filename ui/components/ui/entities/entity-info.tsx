"use client";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import type { ProviderType } from "@/types";

import { getProviderLogo } from "./get-provider-logo";

interface EntityInfoProps {
  cloudProvider: ProviderType;
  entityAlias?: string;
  entityId?: string;
  snippetWidth?: string;
  showConnectionStatus?: boolean;
  maxWidth?: string;
  showCopyAction?: boolean;
}

export const EntityInfo = ({
  cloudProvider,
  entityAlias,
  entityId,
  showConnectionStatus = false,
  maxWidth = "w-[120px]",
  showCopyAction = true,
}: EntityInfoProps) => {
  const canCopy = Boolean(entityId && showCopyAction);

  return (
    <div className="flex items-center gap-2">
      <div className="relative shrink-0">
        {getProviderLogo(cloudProvider)}
        {showConnectionStatus && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="absolute top-[-0.1rem] right-[-0.2rem] h-2 w-2 cursor-pointer rounded-full bg-green-500" />
            </TooltipTrigger>
            <TooltipContent>Connected</TooltipContent>
          </Tooltip>
        )}
      </div>
      <div className={`flex ${maxWidth} flex-col gap-1`}>
        {entityAlias ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <p className="text-text-neutral-primary truncate text-left text-xs font-medium">
                {entityAlias}
              </p>
            </TooltipTrigger>
            <TooltipContent side="top">{entityAlias}</TooltipContent>
          </Tooltip>
        ) : (
          <Tooltip>
            <TooltipTrigger asChild>
              <p className="text-text-neutral-secondary truncate text-left text-xs">
                -
              </p>
            </TooltipTrigger>
            <TooltipContent side="top">No alias</TooltipContent>
          </Tooltip>
        )}
        {entityId && (
          <div className="bg-bg-neutral-tertiary border-border-neutral-tertiary flex w-full min-w-0 items-center gap-1 rounded-xl border px-1.5">
            <Tooltip>
              <TooltipTrigger asChild>
                <p className="text-text-neutral-secondary min-w-0 flex-1 truncate text-left text-xs">
                  {entityId}
                </p>
              </TooltipTrigger>
              <TooltipContent side="top">{entityId}</TooltipContent>
            </Tooltip>
            {canCopy && (
              <CodeSnippet value={entityId} hideCode className="shrink-0" />
            )}
          </div>
        )}
      </div>
    </div>
  );
};
