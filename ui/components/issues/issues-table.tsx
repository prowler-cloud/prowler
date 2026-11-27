"use client";

import { ColumnDef } from "@tanstack/react-table";
import { createContext, useContext, useState } from "react";

import { IssuePanel } from "@/components/issues/issue-panel";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/shadcn";
import { Badge } from "@/components/shadcn/badge/badge";
import { EntityInfo } from "@/components/shadcn/entities";
import { DataTable, DataTableColumnHeader } from "@/components/shadcn/table";
import { SeverityBadge } from "@/components/shadcn/table/severity-badge";
import { TriageStatusBadge } from "@/components/shared/triage/triage-status-badge";
import {
  attackPathLabel,
  LEG_LABELS,
  LEG_STATE_LABELS,
  legBadgeVariant,
  VERDICTS,
} from "@/lib/issues/verdicts";
import { MetaDataProps } from "@/types";
import { IssueResponse, LegName } from "@/types/issues";

type IssueRow = IssueResponse["data"][number];

/** One letter per leg, in the order the legs are asked. */
const LEG_LETTERS: Record<LegName, string> = {
  reachability: "R",
  access: "A",
  target: "T",
  controls: "C",
  verification: "V",
};

const OpenIssueContext = createContext<(id: string) => void>(() => {});

function IssueCell({ issue }: { issue: IssueRow }) {
  const open = useContext(OpenIssueContext);
  const { title, pattern } = issue.attributes;
  const path = attackPathLabel(issue.attributes);
  // Single line like the finding groups title: ellipsis past the max width,
  // the full title in the tooltip.
  return (
    <div className="flex max-w-[500px] min-w-[120px] flex-col gap-0.5">
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            onClick={() => open(issue.id)}
            className="text-text-neutral-primary hover:text-button-tertiary block cursor-pointer truncate border-none bg-transparent p-0 text-left text-sm hover:underline"
          >
            {title}
          </button>
        </TooltipTrigger>
        <TooltipContent side="top">{title}</TooltipContent>
      </Tooltip>
      <p className="text-text-neutral-tertiary truncate text-xs">
        {path ? `${path} · ${pattern}` : pattern}
      </p>
    </div>
  );
}

const columns: ColumnDef<IssueRow>[] = [
  {
    id: "verdict",
    accessorKey: "attributes.verdict",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Verdict"
        param="verdict_rank"
      />
    ),
    cell: ({ row }) => {
      const verdict = VERDICTS.find(
        (v) => v.id === row.original.attributes.verdict,
      );
      return (
        <Badge variant={verdict?.variant ?? "tag"}>
          {verdict?.label ?? row.original.attributes.verdict}
        </Badge>
      );
    },
  },
  {
    id: "issue",
    header: "Issue",
    cell: ({ row }) => <IssueCell issue={row.original} />,
  },
  {
    id: "legs",
    header: "Why",
    cell: ({ row }) => (
      <ul aria-label="Attack path legs" className="flex gap-1">
        {(Object.keys(LEG_LETTERS) as LegName[]).map((name) => {
          const leg = row.original.attributes.legs[name];
          if (!leg) return null;
          const label = `${LEG_LABELS[name]}: ${LEG_STATE_LABELS[leg.state]}`;
          return (
            <li key={name} aria-label={label}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge
                    variant={legBadgeVariant(name, leg.state)}
                    size="sm"
                    aria-hidden="true"
                  >
                    {LEG_LETTERS[name]}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-xs">
                  <p className="font-medium">{label}</p>
                  <p>{leg.text}</p>
                </TooltipContent>
              </Tooltip>
            </li>
          );
        })}
      </ul>
    ),
  },
  {
    id: "severity",
    header: "Severity",
    cell: ({ row }) => (
      <SeverityBadge severity={row.original.attributes.severity} />
    ),
  },
  {
    id: "provider",
    header: "Account",
    cell: ({ row }) => (
      <div className="max-w-[240px]">
        <EntityInfo
          cloudProvider={row.original.attributes.cloud}
          entityAlias={row.original.attributes.account}
        />
      </div>
    ),
  },
  {
    id: "findings",
    accessorKey: "attributes.findings_count",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Findings"
        param="findings_count"
      />
    ),
    cell: ({ row }) => (
      <span className="text-text-neutral-secondary text-sm tabular-nums">
        {row.original.attributes.findings_count.toLocaleString()}
      </span>
    ),
  },
  {
    id: "triage",
    header: "Triage",
    cell: ({ row }) => (
      <TriageStatusBadge
        status={row.original.attributes.triage_status}
        showLabel={false}
      />
    ),
  },
];

export const IssuesTable = ({
  issues,
  metadata,
  providerUids,
}: {
  issues: IssueRow[];
  metadata?: MetaDataProps;
  /** Provider uid by provider id, shown in the panel's Provider field. */
  providerUids?: Record<string, string>;
}) => {
  const [openId, setOpenId] = useState<string | null>(null);
  const openIssue = issues.find((issue) => issue.id === openId);

  return (
    <div className="@container min-w-0">
      <OpenIssueContext value={setOpenId}>
        <DataTable
          columns={columns}
          data={issues}
          metadata={metadata}
          onRowClick={(row) => setOpenId(row.original.id)}
        />
      </OpenIssueContext>
      {openIssue && (
        <IssuePanel
          key={openIssue.id}
          issue={openIssue}
          providerUid={
            providerUids?.[openIssue.relationships?.provider?.data?.id ?? ""]
          }
          open
          onOpenChange={(open) => {
            if (!open) setOpenId(null);
          }}
        />
      )}
    </div>
  );
};
