"use client";

import { AlertCircle } from "lucide-react";

import { Input } from "@/components/shadcn/input/input";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { toNodeKind } from "@/lib/organizations";
import { cn } from "@/lib/utils";
import { APPLY_STATUS, NODE_KIND, OrgCandidate } from "@/types/organizations";
import { TreeRenderItemParams } from "@/types/tree";

const TREE_ITEM_MODE = {
  SELECTION: "selection",
} as const;

type TreeItemMode = (typeof TREE_ITEM_MODE)[keyof typeof TREE_ITEM_MODE];

interface OrgAccountTreeItemProps {
  params: TreeRenderItemParams;
  mode: TreeItemMode;
  candidateLookup: Map<string, OrgCandidate>;
  aliases: Record<string, string>;
  onAliasChange?: (candidateId: string, alias: string) => void;
}

export function OrgAccountTreeItem({
  params,
  mode,
  candidateLookup,
  aliases,
  onAliasChange,
}: OrgAccountTreeItemProps) {
  const { item, isLeaf } = params;
  const candidate = candidateLookup.get(item.id);
  const ItemIcon = item.icon;
  const idColumnClass = "w-44 shrink-0";
  const aliasInputClass = "h-9 w-full max-w-64 text-sm";

  // Container node (OU / folder) — presence in candidateLookup, not an ID
  // prefix, decides this. AWS organizational units keep the editable-name
  // input; other container kinds (e.g. GCP folders) render read-only.
  if (!candidate) {
    const nodeDisplayName = aliases[item.id] ?? item.name;
    const isEditableNode =
      mode === TREE_ITEM_MODE.SELECTION &&
      onAliasChange &&
      toNodeKind(item.kind) === NODE_KIND.ORGANIZATIONAL_UNIT;

    return (
      <div className="flex flex-1 items-center gap-3">
        <div className={`${idColumnClass} flex items-center gap-2`}>
          {ItemIcon && (
            <ItemIcon className="text-muted-foreground size-4 shrink-0" />
          )}
          <span className="text-sm">{item.id}</span>
        </div>
        <div className="min-w-0 flex-1">
          {isEditableNode ? (
            <Input
              className={aliasInputClass}
              placeholder="Name (optional)"
              value={nodeDisplayName}
              onChange={(e) => onAliasChange(item.id, e.target.value)}
              onClick={(e) => e.stopPropagation()}
            />
          ) : (
            <span className="text-muted-foreground line-clamp-1 text-xs">
              {nodeDisplayName}
            </span>
          )}
        </div>
      </div>
    );
  }

  // Any remaining non-leaf node (unexpected fallback).
  if (!isLeaf) {
    return <span className="text-sm font-medium">{item.name}</span>;
  }

  const isBlocked =
    candidate.registration?.apply_status === APPLY_STATUS.BLOCKED;
  const blockedReasons = candidate.registration?.blocked_reasons ?? [];

  return (
    <div className="flex flex-1 items-center gap-3">
      {/* Candidate uid */}
      <div className={cn(idColumnClass, "flex items-center gap-2")}>
        {ItemIcon && (
          <ItemIcon className="text-muted-foreground size-4 shrink-0" />
        )}
        <span className={cn("text-sm", isBlocked && "text-muted-foreground")}>
          {candidate.uid}
        </span>
      </div>

      {/* Name / alias input */}
      <div className="min-w-0 flex-1">
        {mode === TREE_ITEM_MODE.SELECTION && !isBlocked && onAliasChange ? (
          <Input
            className={aliasInputClass}
            placeholder="Name (optional)"
            value={aliases[candidate.uid] ?? candidate.label}
            onChange={(e) => onAliasChange(candidate.uid, e.target.value)}
            onClick={(e) => e.stopPropagation()}
          />
        ) : (
          <span className="text-muted-foreground line-clamp-1 text-xs">
            {aliases[candidate.uid] || candidate.label}
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
