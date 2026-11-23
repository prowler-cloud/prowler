"use client";

import type { ColumnDef } from "@tanstack/react-table";
import Link from "next/link";

import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import { RealtimeEmptyState } from "@/app/(prowler)/realtime/_components/shared/realtime-empty-state";
import {
  asSeverity,
  routeBadge,
  shortArn,
} from "@/app/(prowler)/realtime/_lib/display";
import { checkFindingsHref } from "@/app/(prowler)/realtime/_lib/routes";
import type { RealtimeRankedFinding } from "@/app/(prowler)/realtime/_types";
import { DataTable, SeverityBadge } from "@/components/shadcn/table";
import type { MetaDataProps } from "@/types";

const columns: ColumnDef<RealtimeRankedFinding>[] = [
  {
    accessorKey: "score",
    header: "Score",
    cell: ({ row }) => (
      <span className="text-text-neutral-primary text-sm font-semibold">
        {row.original.score}
      </span>
    ),
  },
  {
    accessorKey: "title",
    header: "Finding",
    cell: ({ row }) => (
      <div className="flex min-w-0 flex-col gap-0.5">
        <Link
          href={checkFindingsHref(row.original.check_id)}
          className="text-text-neutral-primary text-sm font-medium hover:underline"
        >
          {row.original.title}
        </Link>
        <span className="text-text-neutral-tertiary truncate font-mono text-xs">
          {row.original.check_id}
        </span>
      </div>
    ),
  },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ row }) => {
      const severity = asSeverity(row.original.severity);
      return severity ? (
        <SeverityBadge severity={severity} />
      ) : (
        <span className="text-xs">{row.original.severity}</span>
      );
    },
  },
  {
    accessorKey: "resource_uid",
    header: "Resource",
    cell: ({ row }) => (
      <div className="flex max-w-56 flex-col gap-0.5">
        <span
          className="text-text-neutral-secondary truncate font-mono text-xs"
          title={row.original.resource_uid}
        >
          {row.original.resource_uid.startsWith("arn:")
            ? shortArn(row.original.resource_uid)
            : row.original.resource_uid}
        </span>
        <span className="text-text-neutral-tertiary text-xs">
          {row.original.region}
        </span>
      </div>
    ),
  },
  {
    accessorKey: "reasons",
    header: "Why it ranks here",
    cell: ({ row }) => (
      <ul className="text-text-neutral-secondary flex flex-col gap-0.5 text-xs">
        {row.original.reasons.map((reason) => (
          <li key={reason}>{reason}</li>
        ))}
      </ul>
    ),
  },
  {
    accessorKey: "route",
    header: "Handled by",
    cell: ({ row }) => (
      <RealtimeBadge descriptor={routeBadge(row.original.route)} />
    ),
  },
];

interface FindingsTableProps {
  findings: RealtimeRankedFinding[];
  metadata: MetaDataProps;
}

export function FindingsTable({ findings, metadata }: FindingsTableProps) {
  if (findings.length === 0) {
    return (
      <RealtimeEmptyState
        title="No open findings"
        description="Nothing is failing in the latest scan, or the account has not been scanned yet."
      />
    );
  }
  return <DataTable columns={columns} data={findings} metadata={metadata} />;
}
