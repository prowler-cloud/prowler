"use client";

import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
} from "@heroui/dropdown";
import { Row } from "@tanstack/react-table";
import { Ban, MoreVertical, Pencil } from "lucide-react";

import { CustomButton } from "@/components/ui/custom/custom-button";

import { ICON_SIZE } from "./constants";
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

  return (
    <div className="flex justify-end">
      <Dropdown>
        <DropdownTrigger>
          <CustomButton
            ariaLabel="API key actions menu"
            color="transparent"
            size="sm"
            variant="light"
          >
            <MoreVertical size={ICON_SIZE} />
          </CustomButton>
        </DropdownTrigger>
        <DropdownMenu aria-label="API Key actions">
          <DropdownItem
            key="edit"
            startContent={<Pencil size={ICON_SIZE} />}
            onPress={() => onEdit(apiKey)}
          >
            Edit name
          </DropdownItem>
          <DropdownItem
            key="revoke"
            className="text-danger"
            color="danger"
            startContent={<Ban size={ICON_SIZE} />}
            onPress={() => onRevoke(apiKey)}
          >
            Revoke
          </DropdownItem>
        </DropdownMenu>
      </Dropdown>
    </div>
  );
}
