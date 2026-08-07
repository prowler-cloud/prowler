"use client";

import { AlertCircle, CircleSlash } from "lucide-react";

import { Input } from "@/components/shadcn/input/input";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import {
  getCandidateNoun,
  getNodeLabel,
  shortenNodeId,
  toNodeKind,
} from "@/lib/organizations";
import { cn } from "@/lib/utils";
import {
  APPLY_STATUS,
  NODE_KIND,
  OrgCandidate,
  OrgFlowType,
} from "@/types/organizations";
import { TreeRenderItemParams } from "@/types/tree";

const TREE_ITEM_MODE = {
  SELECTION: "selection",
} as const;

type TreeItemMode = (typeof TREE_ITEM_MODE)[keyof typeof TREE_ITEM_MODE];

interface OrgAccountTreeItemProps {
  params: TreeRenderItemParams;
  mode: TreeItemMode;
  orgType: OrgFlowType;
  candidateLookup: Map<string, OrgCandidate>;
  aliases: Record<string, string>;
  onAliasChange?: (candidateId: string, alias: string) => void;
}

/**
 * Why a container row is inert, in this organization's own vocabulary ("No
 * projects available to select in this folder." for GCP, accounts/OUs for AWS).
 * The note is also the icon's `aria-label` so a screen reader reaches it without
 * a hover.
 */
function InertContainerNote({
  orgType,
  kind,
}: {
  orgType: OrgFlowType;
  kind?: string;
}) {
  const note = `No ${getCandidateNoun(orgType).plural} available to select in this ${getNodeLabel(
    orgType,
    toNodeKind(kind),
  ).toLowerCase()}.`;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span role="img" aria-label={note}>
          <CircleSlash className="text-text-neutral-tertiary size-4 shrink-0" />
        </span>
      </TooltipTrigger>
      <TooltipContent side="top">{note}</TooltipContent>
    </Tooltip>
  );
}

/**
 * An identifier in the fixed-width id column. GCP project ids run to 30
 * characters and AWS OU ids longer still, so the text ellipsizes and the full
 * value moves to a tooltip.
 *
 * `shortened` replaces the visible text when ellipsizing would hide everything
 * that distinguishes the value: Azure management-group ids are all prefix, so
 * every group in a tenant reads `/providers/Microsoft....`. The full value then
 * becomes the accessible name too — the tooltip needs a hover, and a screen
 * reader should still get the canonical id.
 */
function TruncatedId({
  value,
  shortened,
  className,
}: {
  value: string;
  shortened?: string;
  className?: string;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={cn("truncate text-sm", className)}
          aria-label={shortened ? value : undefined}
        >
          {shortened ?? value}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top">{value}</TooltipContent>
    </Tooltip>
  );
}

export function OrgAccountTreeItem({
  params,
  mode,
  orgType,
  candidateLookup,
  aliases,
  onAliasChange,
}: OrgAccountTreeItemProps) {
  const { item, isLeaf } = params;
  const candidate = candidateLookup.get(item.id);
  const ItemIcon = item.icon;
  // `min-w-0` alongside the fixed width, or a long id widens the column past
  // 176px and overruns the alias input instead of ellipsizing.
  const idColumnClass = "w-44 min-w-0 shrink-0";
  const aliasInputClass = "h-9 w-full max-w-64 text-sm";

  // Container node (OU / folder) — presence in candidateLookup, not an ID
  // prefix, decides this. AWS organizational units keep the editable-name
  // input; other container kinds (e.g. GCP folders) render read-only.
  if (!candidate) {
    const nodeDisplayName = aliases[item.id] ?? item.name;
    // A disabled container has nothing to apply, so its name would never be sent.
    const isEditableNode =
      mode === TREE_ITEM_MODE.SELECTION &&
      onAliasChange &&
      !item.disabled &&
      toNodeKind(item.kind) === NODE_KIND.ORGANIZATIONAL_UNIT;

    return (
      <div className="flex flex-1 items-center gap-3">
        <div className={cn(idColumnClass, "flex items-center gap-2")}>
          {ItemIcon && (
            <ItemIcon className="text-text-neutral-tertiary size-4 shrink-0" />
          )}
          <TruncatedId value={item.id} shortened={shortenNodeId(item.id)} />
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
            <span className="text-text-neutral-tertiary line-clamp-1 text-xs">
              {nodeDisplayName}
            </span>
          )}
        </div>
        {item.disabled && (
          <InertContainerNote orgType={orgType} kind={item.kind} />
        )}
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
          <ItemIcon className="text-text-neutral-tertiary size-4 shrink-0" />
        )}
        <TruncatedId
          value={candidate.uid}
          className={isBlocked ? "text-text-neutral-tertiary" : undefined}
        />
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
          <span className="text-text-neutral-tertiary line-clamp-1 text-xs">
            {aliases[candidate.uid] || candidate.label}
          </span>
        )}
      </div>

      {/* Blocked reason tooltip */}
      {isBlocked && blockedReasons.length > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <AlertCircle className="text-text-error-primary size-4 shrink-0" />
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
