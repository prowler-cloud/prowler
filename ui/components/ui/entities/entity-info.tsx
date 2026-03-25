"use client";

import { ReactNode } from "react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import type { ProviderType } from "@/types";

import { getProviderLogo } from "./get-provider-logo";

interface EntityInfoProps {
  cloudProvider?: ProviderType;
  icon?: ReactNode;
  /** Small icon rendered inline before the entity alias text */
  nameIcon?: ReactNode;
  entityAlias?: string;
  entityId?: string;
  badge?: string;
  /** Label before the ID value. Defaults to "UID" */
  idLabel?: string;
  showCopyAction?: boolean;
  /** @deprecated No longer used — layout handles overflow naturally */
  maxWidth?: string;
  /** @deprecated No longer used */
  showConnectionStatus?: boolean;
  /** @deprecated No longer used */
  snippetWidth?: string;
}

export const EntityInfo = ({
  cloudProvider,
  icon,
  nameIcon,
  entityAlias,
  entityId,
  badge,
  idLabel = "UID",
  showCopyAction = true,
}: EntityInfoProps) => {
  const canCopy = Boolean(entityId && showCopyAction);
  const renderedIcon =
    icon ?? (cloudProvider ? getProviderLogo(cloudProvider) : null);

  return (
    <div className="flex min-w-0 items-center text-sm">
      <div className="flex min-w-0 items-center gap-4">
        {renderedIcon && <div className="shrink-0">{renderedIcon}</div>}
        <div className="flex min-w-0 flex-col gap-0.5">
          <div className="flex min-w-0 items-center gap-1.5">
            {nameIcon && (
              <span className="text-text-neutral-tertiary shrink-0">
                {nameIcon}
              </span>
            )}
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="truncate font-medium">
                  {entityAlias || entityId || "-"}
                </span>
              </TooltipTrigger>
              <TooltipContent side="top">
                {entityAlias || entityId || "No alias"}
              </TooltipContent>
            </Tooltip>
            {badge && (
              <span className="text-text-neutral-tertiary shrink-0 text-xs">
                ({badge})
              </span>
            )}
          </div>
          {entityId && (
            <div className="flex min-w-0 items-center gap-1">
              <span className="text-text-neutral-tertiary shrink-0 text-xs font-medium">
                {idLabel}:
              </span>
              <CodeSnippet
                value={entityId}
                className="max-w-[160px]"
                hideCopyButton={!canCopy}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
