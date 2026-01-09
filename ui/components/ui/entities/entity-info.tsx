"use client";

import { Tooltip } from "@heroui/tooltip";
import { useEffect, useState } from "react";

import { CopyIcon, DoneIcon } from "@/components/icons";
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
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return undefined;

    const timer = setTimeout(() => setCopied(false), 1400);
    return () => clearTimeout(timer);
  }, [copied]);

  const handleCopyEntityId = async () => {
    if (!entityId) return;

    try {
      await navigator.clipboard.writeText(entityId);
      setCopied(true);
    } catch (_error) {
      setCopied(false);
    }
  };

  const canCopy = Boolean(entityId && showCopyAction);

  return (
    <div className="flex items-center gap-2">
      <div className="relative shrink-0">
        {getProviderLogo(cloudProvider)}
        {showConnectionStatus && (
          <Tooltip
            size="sm"
            content={showConnectionStatus ? "Connected" : "Not Connected"}
          >
            <span
              className={`absolute top-[-0.1rem] right-[-0.2rem] h-2 w-2 cursor-pointer rounded-full ${
                showConnectionStatus ? "bg-green-500" : "bg-red-500"
              }`}
            />
          </Tooltip>
        )}
      </div>
      <div className={`flex ${maxWidth} flex-col gap-1`}>
        {entityAlias ? (
          <Tooltip content={entityAlias} placement="top-start" size="sm">
            <p className="text-text-neutral-primary truncate text-left text-xs font-medium">
              {entityAlias}
            </p>
          </Tooltip>
        ) : (
          <Tooltip content="No alias" placement="top-start" size="sm">
            <p className="text-text-neutral-secondary truncate text-left text-xs">
              -
            </p>
          </Tooltip>
        )}
        {entityId && (
          <div className="flex min-w-0 items-center gap-1">
            <Tooltip content={entityId} placement="top-start" size="sm">
              <p className="text-text-neutral-secondary min-w-0 truncate text-left text-xs">
                {entityId}
              </p>
            </Tooltip>
            {canCopy && (
              <Tooltip
                content={copied ? "Copied" : "Copy to clipboard"}
                placement="top"
                size="sm"
              >
                <button
                  type="button"
                  onClick={handleCopyEntityId}
                  aria-label="Copiar ID de la entidad"
                  className="hover:bg-bg-neutral-tertiary focus-visible:ring-bg-data-info text-text-neutral-secondary hover:text-text-neutral-primary rounded-md p-1 transition-colors focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none"
                >
                  {copied ? <DoneIcon size={14} /> : <CopyIcon size={14} />}
                </button>
              </Tooltip>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
