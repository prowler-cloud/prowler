"use client";

import { AlertCircle } from "lucide-react";

import { Input } from "@/components/shadcn/input/input";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";
import { APPLY_STATUS, DiscoveredAccount } from "@/types/organizations";
import { TreeRenderItemParams } from "@/types/tree";

const TREE_ITEM_MODE = {
  SELECTION: "selection",
} as const;

type TreeItemMode = (typeof TREE_ITEM_MODE)[keyof typeof TREE_ITEM_MODE];

interface OrgAccountTreeItemProps {
  params: TreeRenderItemParams;
  mode: TreeItemMode;
  accountLookup: Map<string, DiscoveredAccount>;
  aliases: Record<string, string>;
  onAliasChange?: (accountId: string, alias: string) => void;
}

export function OrgAccountTreeItem({
  params,
  mode,
  accountLookup,
  aliases,
  onAliasChange,
}: OrgAccountTreeItemProps) {
  const { item, isLeaf } = params;
  const account = accountLookup.get(item.id);
  const isOuNode = item.id.startsWith("ou-");
  const ItemIcon = item.icon;
  const idColumnClass = "w-44 shrink-0";
  const aliasInputClass = "h-9 w-full max-w-64 text-sm";

  // OU nodes: show OU id + alias/name (input in selection mode).
  if (!account && isOuNode) {
    const ouDisplayName = aliases[item.id] ?? item.name;
    const isSelectionMode = mode === TREE_ITEM_MODE.SELECTION && onAliasChange;

    return (
      <div className="flex flex-1 items-center gap-3">
        <div className={`${idColumnClass} flex items-center gap-2`}>
          {ItemIcon && (
            <ItemIcon className="text-muted-foreground size-4 shrink-0" />
          )}
          <span className="text-sm">{item.id}</span>
        </div>
        <div className="min-w-0 flex-1">
          {isSelectionMode ? (
            <Input
              className={aliasInputClass}
              placeholder="Name (optional)"
              value={ouDisplayName}
              onChange={(e) => onAliasChange(item.id, e.target.value)}
              onClick={(e) => e.stopPropagation()}
            />
          ) : (
            <span className="text-muted-foreground line-clamp-1 text-xs">
              {ouDisplayName}
            </span>
          )}
        </div>
      </div>
    );
  }

  // Any remaining non-account node (unexpected fallback).
  if (!account || !isLeaf) {
    return <span className="text-sm font-medium">{item.name}</span>;
  }

  const isBlocked = account.registration?.apply_status === APPLY_STATUS.BLOCKED;
  const blockedReasons = account.registration?.blocked_reasons ?? [];

  return (
    <div className="flex flex-1 items-center gap-3">
      {/* Account ID */}
      <div className={cn(idColumnClass, "flex items-center gap-2")}>
        {ItemIcon && (
          <ItemIcon className="text-muted-foreground size-4 shrink-0" />
        )}
        <span className={cn("text-sm", isBlocked && "text-muted-foreground")}>
          {account.id}
        </span>
      </div>

      {/* Name / alias input */}
      <div className="min-w-0 flex-1">
        {mode === TREE_ITEM_MODE.SELECTION && !isBlocked && onAliasChange ? (
          <Input
            className={aliasInputClass}
            placeholder="Name (optional)"
            value={aliases[account.id] ?? account.name}
            onChange={(e) => onAliasChange(account.id, e.target.value)}
            onClick={(e) => e.stopPropagation()}
          />
        ) : (
          <span className="text-muted-foreground line-clamp-1 text-xs">
            {aliases[account.id] || account.name}
          </span>
        )}
      </div>

      {/* Blocked reason tooltip */}
      {isBlocked && blockedReasons.length > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <AlertCircle className="text-destructive size-4 shrink-0" />
          </TooltipTrigger>
          <TooltipContent>
            <p className="text-xs">{blockedReasons.join(", ")}</p>
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  );
}

export { TREE_ITEM_MODE, type TreeItemMode };
