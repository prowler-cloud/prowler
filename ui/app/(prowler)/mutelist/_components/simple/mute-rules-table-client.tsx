"use client";

import { Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

import { deleteMuteRule } from "@/actions/mute-rules";
import { MuteRuleData } from "@/actions/mute-rules/types";
import { CardTitle } from "@/components/shadcn";
import { FormButtons } from "@/components/shadcn/form";
import { Modal } from "@/components/shadcn/modal";
import { DataTable } from "@/components/shadcn/table";
import { useMuteRuleAction } from "@/hooks/use-mute-rule-action";
import { MetaDataProps } from "@/types";

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
  const [selectedMuteRule, setSelectedMuteRule] = useState<MuteRuleData | null>(
    null,
  );
  const [selectedTargetsRule, setSelectedTargetsRule] =
    useState<MuteRuleTableData | null>(null);
  const { isPending: isDeleting, runAction: runDeleteAction } =
    useMuteRuleAction();

  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isTargetsModalOpen, setIsTargetsModalOpen] = useState(false);

  const handleEditClick = (muteRule: MuteRuleData) => {
    setSelectedMuteRule(muteRule);
    setIsEditModalOpen(true);
  };

  const handleDeleteClick = (muteRule: MuteRuleData) => {
    setSelectedMuteRule(muteRule);
    setIsDeleteModalOpen(true);
  };

  const handleViewTargets = (muteRule: MuteRuleTableData) => {
    setSelectedTargetsRule(muteRule);
    setIsTargetsModalOpen(true);
  };

  const handleEditSuccess = () => {
    setIsEditModalOpen(false);
    router.refresh();
  };

  const handleDeleteSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const formData = new FormData(event.currentTarget);

    runDeleteAction(() => deleteMuteRule(null, formData), {
      onSuccess: () => {
        setIsDeleteModalOpen(false);
        router.refresh();
      },
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
        showSearch
        header={
          <div className="flex w-full items-center justify-between gap-4">
            <div className="flex flex-col gap-0.5">
              <CardTitle>Mutelist Rules</CardTitle>
              <p className="text-text-neutral-tertiary text-xs">
                Rules created from the Findings page apply immediately and can
                be toggled on or off at any time.
              </p>
            </div>
          </div>
        }
      />

      <MuteRuleTargetsModal
        muteRule={selectedTargetsRule}
        open={isTargetsModalOpen}
        onOpenChange={setIsTargetsModalOpen}
      />

      {/* Edit Modal */}
      {selectedMuteRule && (
        <Modal
          open={isEditModalOpen}
          onOpenChange={setIsEditModalOpen}
          title="Edit Mute Rule"
          description="Update the rule metadata without changing the muted findings linked to it."
          size="lg"
        >
          <MuteRuleEditForm
            key={selectedMuteRule.id}
            muteRule={selectedMuteRule}
            onSuccess={handleEditSuccess}
            onCancel={() => setIsEditModalOpen(false)}
          />
        </Modal>
      )}

      {/* Delete Confirmation Modal */}
      {selectedMuteRule && (
        <Modal
          open={isDeleteModalOpen}
          onOpenChange={setIsDeleteModalOpen}
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
              onCancel={() => setIsDeleteModalOpen(false)}
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
