"use client";

import { useDisclosure } from "@heroui/use-disclosure";
import { Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useActionState, useEffect, useRef, useState } from "react";

import { deleteMuteRule } from "@/actions/mute-rules";
import { MuteRuleData } from "@/actions/mute-rules/types";
import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { MetaDataProps } from "@/types";

import { MuteRuleEditForm } from "./mute-rule-edit-form";
import { createMuteRulesColumns } from "./mute-rules-columns";

interface MuteRulesTableClientProps {
  muteRules: MuteRuleData[];
  metadata?: MetaDataProps;
}

export function MuteRulesTableClient({
  muteRules,
  metadata,
}: MuteRulesTableClientProps) {
  const router = useRouter();
  const { toast } = useToast();
  const [selectedMuteRule, setSelectedMuteRule] = useState<MuteRuleData | null>(
    null,
  );

  const editModal = useDisclosure();
  const deleteModal = useDisclosure();
  const deleteModalRef = useRef(deleteModal);
  deleteModalRef.current = deleteModal;

  const [deleteState, deleteAction, isDeleting] = useActionState(
    deleteMuteRule,
    null,
  );

  // Handle delete state changes
  useEffect(() => {
    if (deleteState?.success) {
      toast({
        title: "Success",
        description: deleteState.success,
      });
      deleteModalRef.current.onClose();
      router.refresh();
    } else if (deleteState?.errors?.general) {
      toast({
        variant: "destructive",
        title: "Error",
        description: deleteState.errors.general,
      });
    }
  }, [deleteState, toast, router]);

  const handleEditClick = (muteRule: MuteRuleData) => {
    setSelectedMuteRule(muteRule);
    editModal.onOpen();
  };

  const handleDeleteClick = (muteRule: MuteRuleData) => {
    setSelectedMuteRule(muteRule);
    deleteModal.onOpen();
  };

  const handleEditSuccess = () => {
    editModal.onClose();
    router.refresh();
  };

  const columns = createMuteRulesColumns(handleEditClick, handleDeleteClick);

  return (
    <>
      <DataTable columns={columns} data={muteRules} metadata={metadata} />

      {/* Edit Modal */}
      {selectedMuteRule && (
        <Modal
          open={editModal.isOpen}
          onOpenChange={editModal.onOpenChange}
          title="Edit Mute Rule"
          size="lg"
        >
          <MuteRuleEditForm
            muteRule={selectedMuteRule}
            onSuccess={handleEditSuccess}
            onCancel={editModal.onClose}
          />
        </Modal>
      )}

      {/* Delete Confirmation Modal */}
      {selectedMuteRule && (
        <Modal
          open={deleteModal.isOpen}
          onOpenChange={deleteModal.onOpenChange}
          title="Delete Mute Rule"
          size="md"
        >
          <div className="flex flex-col gap-4">
            <p className="text-default-600 text-sm">
              Are you sure you want to delete the mute rule &quot;
              {selectedMuteRule.attributes.name}&quot;? This action cannot be
              undone.
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
                onClick={deleteModal.onClose}
                disabled={isDeleting}
              >
                Cancel
              </Button>
              <form action={deleteAction}>
                <input type="hidden" name="id" value={selectedMuteRule.id} />
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
        </Modal>
      )}
    </>
  );
}
