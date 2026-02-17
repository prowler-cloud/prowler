"use client";

import { AlertCircle, Check, Loader2 } from "lucide-react";

import { Input } from "@/components/shadcn/input/input";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";
import {
  APPLY_STATUS,
  CONNECTION_TEST_STATUS,
  ConnectionTestStatus,
  DiscoveredAccount,
} from "@/types/organizations";
import { TreeRenderItemParams } from "@/types/tree";

const TREE_ITEM_MODE = {
  SELECTION: "selection",
  TESTING: "testing",
} as const;

type TreeItemMode = (typeof TREE_ITEM_MODE)[keyof typeof TREE_ITEM_MODE];

interface OrgAccountTreeItemProps {
  params: TreeRenderItemParams;
  mode: TreeItemMode;
  accountLookup: Map<string, DiscoveredAccount>;
  aliases: Record<string, string>;
  onAliasChange?: (accountId: string, alias: string) => void;
  connectionResults?: Record<string, ConnectionTestStatus>;
  accountToProviderMap?: Map<string, string>;
}

export function OrgAccountTreeItem({
  params,
  mode,
  accountLookup,
  aliases,
  onAliasChange,
  connectionResults,
  accountToProviderMap,
}: OrgAccountTreeItemProps) {
  const { item, isLeaf } = params;
  const account = accountLookup.get(item.id);

  // Non-leaf nodes (roots/OUs) just render their name
  if (!isLeaf || !account) {
    return <span className="text-sm font-medium">{item.name}</span>;
  }

  const isBlocked = account.registration?.apply_status === APPLY_STATUS.BLOCKED;
  const blockedReasons = account.registration?.blocked_reasons ?? [];

  return (
    <div className="flex flex-1 items-center gap-3">
      {/* Status icon for testing mode */}
      {mode === TREE_ITEM_MODE.TESTING && (
        <TestStatusIcon
          accountId={account.id}
          connectionResults={connectionResults}
          accountToProviderMap={accountToProviderMap}
        />
      )}

      {/* Account ID */}
      <span
        className={cn("shrink-0 text-sm", isBlocked && "text-muted-foreground")}
      >
        {account.id}
      </span>

      {/* Name / alias input */}
      {mode === TREE_ITEM_MODE.SELECTION && !isBlocked && onAliasChange ? (
        <Input
          className="h-7 max-w-48 text-xs"
          placeholder="Name (optional)"
          value={aliases[account.id] ?? account.name}
          onChange={(e) => onAliasChange(account.id, e.target.value)}
          onClick={(e) => e.stopPropagation()}
        />
      ) : (
        <span className="text-muted-foreground text-xs">
          {aliases[account.id] || account.name}
        </span>
      )}

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

interface TestStatusIconProps {
  accountId: string;
  connectionResults?: Record<string, ConnectionTestStatus>;
  accountToProviderMap?: Map<string, string>;
}

function TestStatusIcon({
  accountId,
  connectionResults,
  accountToProviderMap,
}: TestStatusIconProps) {
  const providerId = accountToProviderMap?.get(accountId);
  if (!providerId || !connectionResults) return null;

  const status = connectionResults[providerId];

  if (status === CONNECTION_TEST_STATUS.SUCCESS) {
    return <Check className="size-4 shrink-0 text-green-500" />;
  }

  if (status === CONNECTION_TEST_STATUS.ERROR) {
    return <AlertCircle className="text-destructive size-4 shrink-0" />;
  }

  // pending or undefined = loading
  return (
    <Loader2 className="text-muted-foreground size-4 shrink-0 animate-spin" />
  );
}

export { TREE_ITEM_MODE, type TreeItemMode };
