"use client";

import { ColumnDef } from "@tanstack/react-table";
import { createContext, useContext, useState } from "react";

import { IssuePanel } from "@/components/issues/issue-panel";
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
  return (
    <div className="flex max-w-[420px] min-w-60 flex-col gap-1">
      <button
        type="button"
        onClick={() => open(issue.id)}
        className="text-text-neutral-primary focus-visible:ring-ring/50 self-start rounded-sm text-left text-sm font-medium break-words hover:underline focus-visible:ring-2 focus-visible:outline-none"
      >
        {title}
      </button>
      <p className="text-text-neutral-tertiary flex flex-wrap items-center gap-x-1.5 text-xs">
        {path && (
          <>
            <span className="text-text-neutral-secondary">{path}</span>
            <span aria-hidden="true">·</span>
          </>
        )}
        <span className="break-all">{pattern}</span>
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
            <li key={name} aria-label={label} title={label}>
              <Badge
                variant={legBadgeVariant(name, leg.state)}
                size="sm"
                aria-hidden="true"
              >
                {LEG_LETTERS[name]}
              </Badge>
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
      <EntityInfo
        cloudProvider={row.original.attributes.cloud}
        entityAlias={row.original.attributes.account}
      />
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
}: {
  issues: IssueRow[];
  metadata?: MetaDataProps;
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
          open
          onOpenChange={(open) => {
            if (!open) setOpenId(null);
          }}
        />
      )}
    </div>
  );
};
