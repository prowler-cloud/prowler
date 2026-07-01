"use client";

import { ColumnDef } from "@tanstack/react-table";
import { CloudIcon, FolderIcon, ServerIcon } from "lucide-react";
import { notFound } from "next/navigation";

import { DataTable } from "@/components/ui/table/data-table";
import { DataTableExpandAllToggle } from "@/components/ui/table/data-table-expand-all-toggle";
import { DataTableExpandableCell } from "@/components/ui/table/data-table-expandable-cell";

/**
 * Demo page for the Expandable DataTable component.
 * Only accessible in development mode.
 *
 * Showcases:
 * 1. Hierarchical rows with expand/collapse
 * 2. Expand all / collapse all toggle
 * 3. Row selection with child auto-selection
 */

const IS_DEV = process.env.NODE_ENV === "development";

// Type constants following project conventions
const PROVIDER_TYPES = {
  ORGANIZATION: "organization",
  OU: "ou",
  ACCOUNT: "account",
} as const;
type ProviderType = (typeof PROVIDER_TYPES)[keyof typeof PROVIDER_TYPES];

const PROVIDER_STATUSES = {
  CONNECTED: "connected",
  DISCONNECTED: "disconnected",
  PENDING: "pending",
} as const;
type ProviderStatus =
  (typeof PROVIDER_STATUSES)[keyof typeof PROVIDER_STATUSES];

interface HierarchicalProvider {
  id: string;
  name: string;
  type: ProviderType;
  status: ProviderStatus;
  resourceCount: number;
  children?: HierarchicalProvider[];
}

const tableData: HierarchicalProvider[] = [
  {
    id: "org-1",
    name: "AWS Organization",
    type: PROVIDER_TYPES.ORGANIZATION,
    status: PROVIDER_STATUSES.CONNECTED,
    resourceCount: 1250,
    children: [
      {
        id: "ou-prod",
        name: "Production OU",
        type: PROVIDER_TYPES.OU,
        status: PROVIDER_STATUSES.CONNECTED,
        resourceCount: 800,
        children: [
          {
            id: "acc-prod-1",
            name: "prod-web-services",
            type: PROVIDER_TYPES.ACCOUNT,
            status: PROVIDER_STATUSES.CONNECTED,
            resourceCount: 450,
          },
          {
            id: "acc-prod-2",
            name: "prod-databases",
            type: PROVIDER_TYPES.ACCOUNT,
            status: PROVIDER_STATUSES.CONNECTED,
            resourceCount: 350,
          },
        ],
      },
      {
        id: "ou-dev",
        name: "Development OU",
        type: PROVIDER_TYPES.OU,
        status: PROVIDER_STATUSES.CONNECTED,
        resourceCount: 450,
        children: [
          {
            id: "acc-dev-1",
            name: "dev-sandbox",
            type: PROVIDER_TYPES.ACCOUNT,
            status: PROVIDER_STATUSES.PENDING,
            resourceCount: 200,
          },
          {
            id: "acc-dev-2",
            name: "dev-testing",
            type: PROVIDER_TYPES.ACCOUNT,
            status: PROVIDER_STATUSES.DISCONNECTED,
            resourceCount: 250,
          },
        ],
      },
    ],
  },
];

const STATUS_COLORS = {
  connected: "text-green-500",
  disconnected: "text-red-500",
  pending: "text-yellow-500",
} as const;

const TYPE_ICONS = {
  organization: ServerIcon,
  ou: FolderIcon,
  account: CloudIcon,
} as const;

const columns: ColumnDef<HierarchicalProvider>[] = [
  {
    accessorKey: "name",
    size: 300,
    header: ({ table }) => (
      <div className="flex items-center gap-2">
        <DataTableExpandAllToggle table={table} />
        <span>Name</span>
      </div>
    ),
    cell: ({ row }) => {
      const Icon = TYPE_ICONS[row.original.type];
      return (
        <DataTableExpandableCell row={row}>
          <div className="flex items-center gap-2">
            <Icon className="h-4 w-4 shrink-0" />
            <span>{row.original.name}</span>
          </div>
        </DataTableExpandableCell>
      );
    },
  },
  {
    accessorKey: "type",
    size: 120,
    header: "Type",
    cell: ({ row }) => <span className="capitalize">{row.original.type}</span>,
  },
  {
    accessorKey: "status",
    size: 120,
    header: "Status",
    cell: ({ row }) => (
      <span className={STATUS_COLORS[row.original.status]}>
        {row.original.status}
      </span>
    ),
  },
  {
    accessorKey: "resourceCount",
    size: 100,
    header: "Resources",
    cell: ({ row }) => row.original.resourceCount.toLocaleString(),
  },
];

export default function DemoExpandableTablePage() {
  if (!IS_DEV) {
    notFound();
  }

  return (
    <div className="container mx-auto space-y-12 p-8">
      <h1 className="text-3xl font-bold">Expandable DataTable Demo</h1>

      {/* Expandable DataTable */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-semibold">Expandable DataTable</h2>
          <p className="text-text-neutral-secondary text-sm">
            Table with hierarchical rows. Click chevron to expand/collapse, or
            use the header icon to expand/collapse all.
          </p>
        </div>

        <DataTable
          columns={columns}
          data={tableData}
          getSubRows={(row) => row.children}
          defaultExpanded={true}
        />
      </section>

      {/* Expandable DataTable with Row Selection */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-semibold">
            Expandable DataTable with Row Selection
          </h2>
          <p className="text-text-neutral-secondary text-sm">
            Selecting a parent auto-selects all children
            (enableSubRowSelection).
          </p>
        </div>

        <DataTable
          columns={columns}
          data={tableData}
          getSubRows={(row) => row.children}
          enableRowSelection
          enableSubRowSelection
          defaultExpanded={{ "org-1": true, "ou-prod": true }}
        />
      </section>
    </div>
  );
}
