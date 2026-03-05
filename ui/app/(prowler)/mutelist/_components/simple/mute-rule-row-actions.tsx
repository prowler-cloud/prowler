"use client";

import { Pencil, Trash2 } from "lucide-react";

import { MuteRuleData } from "@/actions/mute-rules/types";
import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
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
      >
        <ActionDropdownItem
          icon={<Pencil />}
          label="Edit Mute Rule"
          onSelect={() => onEdit(muteRule)}
        />
        <ActionDropdownDangerZone>
          <ActionDropdownItem
            icon={<Trash2 />}
            label="Delete Mute Rule"
            destructive
            onSelect={() => onDelete(muteRule)}
          />
        </ActionDropdownDangerZone>
      </ActionDropdown>
    </div>
  );
}
