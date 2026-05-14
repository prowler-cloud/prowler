"use client";

import { Row } from "@tanstack/react-table";
import { Pencil, Trash2 } from "lucide-react";

import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
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
      <ActionDropdown>
        <ActionDropdownItem
          icon={<Pencil />}
          label="Edit API Key"
          onSelect={() => onEdit(apiKey)}
        />
        {canRevoke && (
          <ActionDropdownDangerZone>
            <ActionDropdownItem
              icon={<Trash2 />}
              label="Revoke API Key"
              destructive
              onSelect={() => onRevoke(apiKey)}
            />
          </ActionDropdownDangerZone>
        )}
      </ActionDropdown>
    </div>
  );
}
