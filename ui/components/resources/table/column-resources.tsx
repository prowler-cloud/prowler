"use client";

import { ColumnDef } from "@tanstack/react-table";
import { AlertTriangle, Eye, MoreVertical } from "lucide-react";
import { useState } from "react";

import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { EntityInfo } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { getGroupLabel } from "@/lib/categories";
import { ProviderType, ResourceProps } from "@/types";

import { ResourceDetail } from "./resource-detail";

const getResourceData = (
  row: { original: ResourceProps },
  field: keyof ResourceProps["attributes"],
) => {
  return row.original.attributes?.[field];
};

const getProviderData = (
  row: { original: ResourceProps },
  field: keyof ResourceProps["relationships"]["provider"]["data"]["attributes"],
) => {
  return (
    row.original.relationships?.provider?.data?.attributes?.[field] ??
    `No ${field} found in provider`
  );
};

// Component for resource name that opens the detail drawer
const ResourceNameCell = ({ row }: { row: { original: ResourceProps } }) => {
  const resourceName = row.original.attributes?.name;
  const resourceUid = row.original.attributes?.uid;
  const displayName =
    typeof resourceName === "string" && resourceName.trim().length > 0
      ? resourceName
      : "Unnamed resource";

  // Note: We don't use defaultOpen here because ResourceDetailsSheet (rendered at page level)
  // already handles opening the drawer when resourceId is in the URL. Using defaultOpen={true}
  // here would cause duplicate drawers to render.
  return (
    <div className="flex items-center gap-2">
      <ResourceDetail
        resourceDetails={row.original}
        trigger={
          <div className="max-w-[200px]">
            <p className="text-text-neutral-primary hover:text-button-tertiary cursor-pointer text-left text-sm break-words whitespace-normal hover:underline">
              {displayName}
            </p>
          </div>
        }
      />
      {resourceUid && <CodeSnippet value={resourceUid} hideCode />}
    </div>
  );
};

// Component for failed findings badge with warning style
const FailedFindingsBadge = ({ count }: { count: number }) => {
  if (count === 0) {
    return (
      <span className="inline-flex h-6 items-center justify-center rounded-full bg-green-100 px-2 text-xs font-semibold text-green-800 dark:bg-green-900/30 dark:text-green-400">
        0
      </span>
    );
  }

  return (
    <span className="inline-flex h-6 items-center gap-1 rounded-full bg-red-100 px-2 text-xs font-semibold text-red-800 dark:bg-red-900/30 dark:text-red-400">
      <AlertTriangle className="h-3 w-3" />
      {count}
    </span>
  );
};

// Row actions dropdown
const ResourceRowActions = ({ row }: { row: { original: ResourceProps } }) => {
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const resourceName = row.original.attributes?.name || "Resource";

  return (
    <>
      <div className="flex items-center justify-end">
        <ActionDropdown
          trigger={
            <button
              type="button"
              aria-label="Resource actions"
              className="hover:bg-bg-neutral-tertiary rounded-md p-1 transition-colors"
            >
              <MoreVertical className="text-text-neutral-secondary size-5" />
            </button>
          }
          ariaLabel="Resource actions"
        >
          <ActionDropdownItem
            icon={<Eye className="size-5" />}
            label="View details"
            description={`View details for ${resourceName}`}
            onSelect={() => setIsDrawerOpen(true)}
          />
        </ActionDropdown>
      </div>

      <ResourceDetail
        resourceDetails={row.original}
        open={isDrawerOpen}
        onOpenChange={setIsDrawerOpen}
        trigger={<span className="hidden" />}
      />
    </>
  );
};

// Column definitions for resources table
export const ColumnResources: ColumnDef<ResourceProps>[] = [
  // Name column
  {
    accessorKey: "resourceName",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Name" />
    ),
    cell: ({ row }) => <ResourceNameCell row={row} />,
    enableSorting: false,
  },
  // Provider Account column
  {
    accessorKey: "provider",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Provider Account" />
    ),
    cell: ({ row }) => {
      const provider = getProviderData(row, "provider");
      const alias = getProviderData(row, "alias");
      const uid = getProviderData(row, "uid");
      return (
        <EntityInfo
          cloudProvider={provider as ProviderType}
          entityAlias={alias && typeof alias === "string" ? alias : undefined}
          entityId={uid && typeof uid === "string" ? uid : undefined}
        />
      );
    },
    enableSorting: false,
  },
  // Failed Findings column
  {
    accessorKey: "failedFindings",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Failed Findings" />
    ),
    cell: ({ row }) => {
      const failedFindingsCount = getResourceData(
        row,
        "failed_findings_count",
      ) as number;

      return <FailedFindingsBadge count={failedFindingsCount ?? 0} />;
    },
    enableSorting: false,
  },
  // Group column
  {
    accessorKey: "groups",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Group" param="groups" />
    ),
    cell: ({ row }) => {
      const groups = getResourceData(row, "groups") as string[] | null;

      if (!groups || groups.length === 0) {
        return <p className="text-text-neutral-primary text-sm">-</p>;
      }

      const displayLabel = getGroupLabel(groups[0]);
      const extraCount = groups.length - 1;

      return (
        <div className="flex items-center gap-1">
          <p className="text-text-neutral-primary max-w-[120px] truncate text-sm">
            {displayLabel}
          </p>
          {extraCount > 0 && (
            <span className="text-text-neutral-secondary text-xs">
              +{extraCount}
            </span>
          )}
        </div>
      );
    },
    enableSorting: false,
  },
  // Type column
  {
    accessorKey: "type",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Type" param="type" />
    ),
    cell: ({ row }) => {
      const type = getResourceData(row, "type");

      return (
        <p className="text-text-neutral-primary max-w-[150px] truncate text-sm">
          {typeof type === "string" ? type : "-"}
        </p>
      );
    },
  },
  // Region column
  {
    accessorKey: "region",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Region" param="region" />
    ),
    cell: ({ row }) => {
      const region = getResourceData(row, "region");

      return (
        <p className="text-text-neutral-primary max-w-[120px] truncate text-sm">
          {typeof region === "string" ? region : "-"}
        </p>
      );
    },
  },
  // Service column
  {
    accessorKey: "service",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Service" param="service" />
    ),
    cell: ({ row }) => {
      const service = getResourceData(row, "service");

      return (
        <p className="text-text-neutral-primary max-w-[150px] truncate text-sm">
          {typeof service === "string" ? service : "-"}
        </p>
      );
    },
  },
  // Actions column
  {
    id: "actions",
    header: () => <div className="w-10" />,
    cell: ({ row }) => <ResourceRowActions row={row} />,
    enableSorting: false,
  },
];
