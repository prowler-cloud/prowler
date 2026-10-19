"use client";

import { ColumnDef, Row } from "@tanstack/react-table";
import { ChevronDown, ChevronRight } from "lucide-react";
import { createContext, useContext, useState } from "react";

import { IssueDetail } from "@/components/issues/issue-detail";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { EntityInfo } from "@/components/shadcn/entities";
import { DataTable, DataTableColumnHeader } from "@/components/shadcn/table";
import { TableCell, TableRow } from "@/components/shadcn/table/table";
import { VERDICTS } from "@/lib/issues/verdicts";
import { MetaDataProps } from "@/types";
import { IssueResponse } from "@/types/issues";

type IssueRow = IssueResponse["data"][number];

interface IssueExpansion {
  openId: string | null;
  toggle: (id: string) => void;
}

const IssueExpansionContext = createContext<IssueExpansion | null>(null);

function IssueExpandCell({ row }: { row: Row<IssueRow> }) {
  const expansion = useContext(IssueExpansionContext);
  const expanded = expansion?.openId === row.original.id;
  return (
    <Button
      variant="ghost"
      size="icon-sm"
      aria-label={`${expanded ? "Collapse" : "Expand"} ${row.original.attributes.title}`}
      aria-expanded={expanded}
      aria-controls={expanded ? `issue-${row.original.id}` : undefined}
      onClick={() => expansion?.toggle(row.original.id)}
    >
      {expanded ? (
        <ChevronDown aria-hidden="true" />
      ) : (
        <ChevronRight aria-hidden="true" />
      )}
    </Button>
  );
}

const columns: ColumnDef<IssueRow>[] = [
  { id: "expand", header: "", cell: IssueExpandCell },
  {
    id: "issue",
    header: "Issue",
    cell: ({ row }) => (
      <div className="max-w-[360px] min-w-0">
        <p className="text-text-neutral-primary text-sm font-medium break-words">
          {row.original.attributes.title}
        </p>
        <p className="text-text-neutral-tertiary truncate text-xs">
          {row.original.attributes.pattern}
        </p>
      </div>
    ),
  },
  {
    id: "provider",
    header: "Provider",
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
        {row.original.attributes.findings_count}
      </span>
    ),
  },
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
];

export const IssuesTable = ({
  issues,
  metadata,
}: {
  issues: IssueRow[];
  metadata?: MetaDataProps;
}) => {
  // One open row at a time: each detail fetches its issue's resource ids.
  const [openId, setOpenId] = useState<string | null>(null);

  const toggleRow = (id: string) =>
    setOpenId((current) => (current === id ? null : id));
  const renderAfterRow = (row: Row<IssueRow>) =>
    row.original.id === openId ? (
      <TableRow>
        <TableCell colSpan={columns.length}>
          <div
            id={`issue-${row.original.id}`}
            className="sticky left-0 w-[calc(100cqw-4rem)] min-w-0"
          >
            <IssueDetail
              key={`${row.original.id}-${row.original.attributes.updated_at}`}
              id={row.original.id}
              issue={row.original.attributes}
              scanId={row.original.relationships?.scan?.data?.id}
              providerId={row.original.relationships?.provider?.data?.id}
            />
          </div>
        </TableCell>
      </TableRow>
    ) : null;

  return (
    <div className="@container min-w-0">
      <IssueExpansionContext value={{ openId, toggle: toggleRow }}>
        <DataTable
          columns={columns}
          data={issues}
          metadata={metadata}
          onRowClick={(row) => toggleRow(row.original.id)}
          renderAfterRow={renderAfterRow}
        />
      </IssueExpansionContext>
    </div>
  );
};
