"use client";

import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
} from "@heroui/dropdown";
import { Row } from "@tanstack/react-table";
import { MoreVertical, Pencil, Trash2 } from "lucide-react";

import { CustomButton } from "@/components/ui/custom/custom-button";

import { ICON_SIZE } from "./constants";
import { ApiKeyData } from "./types";

interface DataTableRowActionsProps {
  row: Row<ApiKeyData>;
  onEdit: (apiKey: ApiKeyData) => void;
  onDelete: (apiKey: ApiKeyData) => void;
}

export function DataTableRowActions({
  row,
  onEdit,
  onDelete,
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
            key="delete"
            className="text-danger"
            color="danger"
            startContent={<Trash2 size={ICON_SIZE} />}
            onPress={() => onDelete(apiKey)}
          >
            Delete
          </DropdownItem>
        </DropdownMenu>
      </Dropdown>
    </div>
  );
}

