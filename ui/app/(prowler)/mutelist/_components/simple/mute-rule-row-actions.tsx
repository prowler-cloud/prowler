"use client";

import { Pencil, Trash2 } from "lucide-react";

import { MuteRuleData } from "@/actions/mute-rules/types";
import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownItem,
  ActionDropdownLabel,
  ActionDropdownSeparator,
} from "@/components/shadcn/dropdown";

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
      <ActionDropdown
        trigger={
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
        }
        label="Actions"
      >
        <ActionDropdownItem
          icon={<Pencil />}
          label="Edit"
          description="Edit rule name and reason"
          onSelect={() => onEdit(muteRule)}
        />
        <ActionDropdownSeparator />
        <ActionDropdownLabel>Danger zone</ActionDropdownLabel>
        <ActionDropdownItem
          icon={<Trash2 />}
          label="Delete"
          description="Delete this mute rule"
          destructive
          onSelect={() => onDelete(muteRule)}
        />
      </ActionDropdown>
    </div>
  );
}
