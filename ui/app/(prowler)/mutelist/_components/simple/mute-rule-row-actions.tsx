"use client";

import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownSection,
  DropdownTrigger,
} from "@heroui/dropdown";
import { Pencil, Trash2 } from "lucide-react";

import { MuteRuleData } from "@/actions/mute-rules/types";
import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";

interface MuteRuleRowActionsProps {
  muteRule: MuteRuleData;
  onEdit: (muteRule: MuteRuleData) => void;
  onDelete: (muteRule: MuteRuleData) => void;
}

export function MuteRuleRowActions({
  muteRule,
  onEdit,
  onDelete,
}: MuteRuleRowActionsProps) {
  return (
    <div className="flex items-center justify-center px-2">
      <Dropdown
        className="border-border-neutral-secondary bg-bg-neutral-secondary border shadow-xl"
        placement="bottom"
      >
        <DropdownTrigger>
          <Button
            variant="outline"
            size="icon-sm"
            className="size-7 rounded-full"
          >
            <VerticalDotsIcon
              size={16}
              className="text-text-neutral-secondary"
            />
          </Button>
        </DropdownTrigger>
        <DropdownMenu
          closeOnSelect
          aria-label="Mute rule actions"
          color="default"
          variant="flat"
        >
          <DropdownSection title="Actions">
            <DropdownItem
              key="edit"
              description="Edit rule name and reason"
              textValue="Edit"
              startContent={
                <Pencil className="text-default-500 pointer-events-none size-4 shrink-0" />
              }
              onPress={() => onEdit(muteRule)}
            >
              Edit
            </DropdownItem>
            <DropdownItem
              key="delete"
              description="Delete this mute rule"
              textValue="Delete"
              className="text-danger"
              color="danger"
              classNames={{
                description: "text-danger",
              }}
              startContent={
                <Trash2 className="pointer-events-none size-4 shrink-0" />
              }
              onPress={() => onDelete(muteRule)}
            >
              Delete
            </DropdownItem>
          </DropdownSection>
        </DropdownMenu>
      </Dropdown>
    </div>
  );
}
