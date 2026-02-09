"use client";

import { Row } from "@tanstack/react-table";
import { Pencil, Trash2 } from "lucide-react";

import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownItem,
  ActionDropdownLabel,
  ActionDropdownSeparator,
} from "@/components/shadcn/dropdown";

import { EnrichedApiKey } from "./types";

interface DataTableRowActionsProps {
  row: Row<EnrichedApiKey>;
  onEdit: (apiKey: EnrichedApiKey) => void;
  onRevoke: (apiKey: EnrichedApiKey) => void;
}

export function DataTableRowActions({
  row,
  onEdit,
  onRevoke,
}: DataTableRowActionsProps) {
  const apiKey = row.original;
  const isRevoked = apiKey.attributes.revoked;
  const isExpired = new Date(apiKey.attributes.expires_at) < new Date();
  const canRevoke = !isRevoked && !isExpired;

  return (
    <div className="relative flex items-center justify-end gap-2">
      <ActionDropdown
        trigger={
          <Button variant="ghost" size="icon-sm" className="rounded-full">
            <VerticalDotsIcon className="text-slate-400" />
          </Button>
        }
        label="Actions"
      >
        <ActionDropdownItem
          icon={<Pencil />}
          label="Edit name"
          description="Edit the API key name"
          onSelect={() => onEdit(apiKey)}
        />
        {canRevoke && (
          <>
            <ActionDropdownSeparator />
            <ActionDropdownLabel>Danger zone</ActionDropdownLabel>
            <ActionDropdownItem
              icon={<Trash2 />}
              label="Revoke"
              description="Revoke this API key permanently"
              destructive
              onSelect={() => onRevoke(apiKey)}
            />
          </>
        )}
      </ActionDropdown>
    </div>
  );
}
