"use client";

import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownSection,
  DropdownTrigger,
} from "@heroui/dropdown";
import { Pencil, Trash2 } from "lucide-react";
import { useActionState, useEffect, useState } from "react";

import { deleteMuteRule } from "@/actions/mute-rules";
import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { CustomAlertModal } from "@/components/ui/custom";
import { MuteRuleData } from "@/types/mute-rules";

import { MuteRuleEditForm } from "./mute-rule-edit-form";

interface MuteRuleRowActionsProps {
  muteRule: MuteRuleData;
}

export function MuteRuleRowActions({ muteRule }: MuteRuleRowActionsProps) {
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const { toast } = useToast();

  const [deleteState, deleteAction, isDeleting] = useActionState(
    deleteMuteRule,
    null,
  );

  useEffect(() => {
    if (deleteState?.success) {
      toast({
        title: "Success",
        description: deleteState.success,
      });
      setIsDeleteModalOpen(false);
    } else if (deleteState?.errors?.general) {
      toast({
        variant: "destructive",
        title: "Error",
        description: deleteState.errors.general,
      });
    }
  }, [deleteState, toast]);

  return (
    <>
      {/* Edit Modal */}
      <CustomAlertModal
        isOpen={isEditModalOpen}
        onOpenChange={setIsEditModalOpen}
        title="Edit Mute Rule"
        size="lg"
      >
        <MuteRuleEditForm
          muteRule={muteRule}
          setIsOpen={setIsEditModalOpen}
          onCancel={() => setIsEditModalOpen(false)}
        />
      </CustomAlertModal>

      {/* Delete Confirmation Modal */}
      <CustomAlertModal
        isOpen={isDeleteModalOpen}
        onOpenChange={setIsDeleteModalOpen}
        title="Delete Mute Rule"
        size="md"
      >
        <div className="flex flex-col gap-4">
          <p className="text-default-600 text-sm">
            Are you sure you want to delete the mute rule &quot;
            {muteRule.attributes.name}&quot;? This action cannot be undone.
          </p>
          <p className="text-default-500 text-xs">
            Note: This will not unmute the findings that were muted by this
            rule.
          </p>
          <div className="flex w-full justify-end gap-4">
            <Button
              type="button"
              variant="ghost"
              size="lg"
              onClick={() => setIsDeleteModalOpen(false)}
              disabled={isDeleting}
            >
              Cancel
            </Button>
            <form action={deleteAction}>
              <input type="hidden" name="id" value={muteRule.id} />
              <Button
                type="submit"
                variant="destructive"
                size="lg"
                disabled={isDeleting}
              >
                <Trash2 className="size-4" />
                {isDeleting ? "Deleting..." : "Delete"}
              </Button>
            </form>
          </div>
        </div>
      </CustomAlertModal>

      {/* Actions Dropdown */}
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
                onPress={() => setIsEditModalOpen(true)}
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
                onPress={() => setIsDeleteModalOpen(true)}
              >
                Delete
              </DropdownItem>
            </DropdownSection>
          </DropdownMenu>
        </Dropdown>
      </div>
    </>
  );
}
