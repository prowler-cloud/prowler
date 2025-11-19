"use client";

import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownSection,
  DropdownTrigger,
} from "@heroui/dropdown";
import {
  DeleteDocumentBulkIcon,
  EditDocumentBulkIcon,
} from "@heroui/shared-icons";
import { Row } from "@tanstack/react-table";
import clsx from "clsx";

import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";

import { EnrichedApiKey } from "./types";

interface DataTableRowActionsProps {
  row: Row<EnrichedApiKey>;
  onEdit: (apiKey: EnrichedApiKey) => void;
  onRevoke: (apiKey: EnrichedApiKey) => void;
}

const iconClasses = "text-2xl text-default-500 pointer-events-none shrink-0";

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
      <Dropdown
        className="border-border-neutral-secondary bg-bg-neutral-secondary border shadow-xl"
        placement="bottom"
      >
        <DropdownTrigger>
          <Button variant="ghost" size="icon-sm" className="rounded-full">
            <VerticalDotsIcon className="text-slate-400" />
          </Button>
        </DropdownTrigger>
        <DropdownMenu
          closeOnSelect
          aria-label="API Key actions"
          color="default"
          variant="flat"
        >
          <DropdownSection title="Actions">
            <DropdownItem
              key="edit"
              description="Edit the API key name"
              textValue="Edit name"
              startContent={<EditDocumentBulkIcon className={iconClasses} />}
              onPress={() => onEdit(apiKey)}
            >
              Edit name
            </DropdownItem>
          </DropdownSection>
          {canRevoke ? (
            <DropdownSection title="Danger zone">
              <DropdownItem
                key="revoke"
                className="text-text-error"
                color="danger"
                description="Revoke this API key permanently"
                textValue="Revoke"
                startContent={
                  <DeleteDocumentBulkIcon
                    className={clsx(iconClasses, "!text-text-error")}
                  />
                }
                onPress={() => onRevoke(apiKey)}
              >
                Revoke
              </DropdownItem>
            </DropdownSection>
          ) : null}
        </DropdownMenu>
      </Dropdown>
    </div>
  );
}
