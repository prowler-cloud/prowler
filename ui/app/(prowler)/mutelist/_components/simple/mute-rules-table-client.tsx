"use client";

import { useDisclosure } from "@heroui/use-disclosure";
import { RowSelectionState } from "@tanstack/react-table";
import { Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { FormEvent, useState, useTransition } from "react";

import { deleteMuteRule } from "@/actions/mute-rules";
import { MuteRuleData } from "@/actions/mute-rules/types";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { FormButtons } from "@/components/ui/form";
import { DataTable } from "@/components/ui/table";
import { MetaDataProps } from "@/types";

import { FloatingBulkDeleteButton } from "./floating-bulk-delete-button";
import { MuteRuleEditForm } from "./mute-rule-edit-form";
import { MuteRuleTableData } from "./mute-rule-target-previews";
import { MuteRuleTargetsModal } from "./mute-rule-targets-modal";
import { createMuteRulesColumns } from "./mute-rules-columns";

interface MuteRulesTableClientProps {
  muteRules: MuteRuleTableData[];
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
  const [selectedTargetsRule, setSelectedTargetsRule] =
    useState<MuteRuleTableData | null>(null);
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [isDeleting, startDeleteTransition] = useTransition();

  const editModal = useDisclosure();
  const deleteModal = useDisclosure();
  const targetsModal = useDisclosure();

  const selectedIds = Object.entries(rowSelection)
    .filter(([, selected]) => selected)
    .map(([id]) => id);
  const selectedRules = muteRules.filter((rule) =>
    selectedIds.includes(rule.id),
  );

  const handleEditClick = (muteRule: MuteRuleData) => {
    setSelectedMuteRule(muteRule);
    editModal.onOpen();
  };

  const handleDeleteClick = (muteRule: MuteRuleData) => {
    setSelectedMuteRule(muteRule);
    deleteModal.onOpen();
  };

  const handleViewTargets = (muteRule: MuteRuleTableData) => {
    setSelectedTargetsRule(muteRule);
    targetsModal.onOpen();
  };

  const handleEditSuccess = () => {
    editModal.onClose();
    router.refresh();
  };

  const handleDeleteSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const formData = new FormData(event.currentTarget);

    startDeleteTransition(() => {
      void (async () => {
        const result = await deleteMuteRule(null, formData);

        if (result?.success) {
          toast({
            title: "Success",
            description: result.success,
          });
          deleteModal.onClose();
          router.refresh();
          return;
        }

        if (result?.errors?.general) {
          toast({
            variant: "destructive",
            title: "Error",
            description: result.errors.general,
          });
        }
      })();
    });
  };

  const columns = createMuteRulesColumns(
    handleEditClick,
    handleDeleteClick,
    handleViewTargets,
  );

  return (
    <>
      <DataTable
        columns={columns}
        data={muteRules}
        metadata={metadata}
        enableRowSelection
        rowSelection={rowSelection}
        onRowSelectionChange={setRowSelection}
        getRowId={(rule) => rule.id}
        showSearch
        searchPlaceholder="Search rules by name or reason..."
      />

      {selectedRules.length > 0 ? (
        <FloatingBulkDeleteButton
          selectedCount={selectedRules.length}
          selectedRules={selectedRules}
          onComplete={() => {
            setRowSelection({});
            router.refresh();
          }}
        />
      ) : null}

      <MuteRuleTargetsModal
        muteRule={selectedTargetsRule}
        open={targetsModal.isOpen}
        onOpenChange={targetsModal.onOpenChange}
      />

      {/* Edit Modal */}
      {selectedMuteRule && (
        <Modal
          open={editModal.isOpen}
          onOpenChange={editModal.onOpenChange}
          title="Edit Mute Rule"
          description="Update the rule metadata without changing the muted findings linked to it."
          size="lg"
        >
          <MuteRuleEditForm
            key={selectedMuteRule.id}
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
          description="Remove this rule from Mutelist. Existing muted findings will remain muted."
          size="md"
        >
          <form onSubmit={handleDeleteSubmit} className="flex flex-col gap-5">
            <input type="hidden" name="id" value={selectedMuteRule.id} />

            <div className="border-border-neutral-secondary bg-bg-neutral-tertiary rounded-xl border p-4">
              <p className="text-text-neutral-tertiary text-xs font-medium tracking-[0.08em] uppercase">
                Rule to delete
              </p>
              <p className="text-text-neutral-primary mt-2 text-sm font-medium">
                {selectedMuteRule.attributes.name}
              </p>
              <p className="text-text-neutral-secondary mt-1 text-sm">
                Deleting this rule removes it from Mutelist immediately.
              </p>
              <p className="text-text-neutral-tertiary mt-1 text-xs">
                This action will not unmute the findings that were already muted
                by the rule.
              </p>
            </div>

            <FormButtons
              onCancel={deleteModal.onClose}
              submitText={isDeleting ? "Deleting..." : "Delete"}
              isDisabled={isDeleting}
              submitColor="danger"
              rightIcon={isDeleting ? undefined : <Trash2 className="size-4" />}
            />
          </form>
        </Modal>
      )}
    </>
  );
}
