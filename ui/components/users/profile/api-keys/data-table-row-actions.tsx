"use client";

import { Button } from "@heroui/button";
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
        className="dark:bg-prowler-blue-800 shadow-xl"
        placement="bottom"
      >
        <DropdownTrigger>
          <Button isIconOnly radius="full" size="sm" variant="light">
            <VerticalDotsIcon className="text-default-400" />
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
                className="text-danger"
                color="danger"
                description="Revoke this API key permanently"
                textValue="Revoke"
                startContent={
                  <DeleteDocumentBulkIcon
                    className={clsx(iconClasses, "!text-danger")}
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
