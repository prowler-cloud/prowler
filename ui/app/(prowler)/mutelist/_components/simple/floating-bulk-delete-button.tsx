"use client";

import { Trash2 } from "lucide-react";
import { FormEvent, useState, useTransition } from "react";

import { bulkDeleteMuteRules } from "@/actions/mute-rules";
import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { FormButtons } from "@/components/ui/form";

import { MuteRuleTableData } from "./mute-rule-target-previews";

const MAX_PREVIEW_NAMES = 5;

interface FloatingBulkDeleteButtonProps {
  selectedCount: number;
  selectedRules: MuteRuleTableData[];
  onComplete: () => void;
}

export function FloatingBulkDeleteButton({
  selectedCount,
  selectedRules,
  onComplete,
}: FloatingBulkDeleteButtonProps) {
  const { toast } = useToast();
  const [isOpen, setIsOpen] = useState(false);
  const [isPending, startTransition] = useTransition();

  const pluralSuffix = selectedCount === 1 ? "" : "s";
  const previewNames = selectedRules
    .slice(0, MAX_PREVIEW_NAMES)
    .map((rule) => rule.attributes.name);
  const hiddenPreviewCount = Math.max(
    selectedRules.length - previewNames.length,
    0,
  );

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const formData = new FormData();
    formData.set("ids", JSON.stringify(selectedRules.map((rule) => rule.id)));

    startTransition(() => {
      void (async () => {
        const result = await bulkDeleteMuteRules(null, formData);

        if (result?.success) {
          toast({
            title: "Success",
            description: result.success,
          });
          setIsOpen(false);
          onComplete();
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

  return (
    <>
      <div className="animate-in fade-in slide-in-from-bottom-4 fixed right-6 bottom-6 z-50 duration-300">
        <Button
          type="button"
          variant="destructive"
          size="lg"
          className="shadow-lg"
          onClick={() => setIsOpen(true)}
        >
          <Trash2 className="size-4" />
          {`Delete ${selectedCount} rule${pluralSuffix}`}
        </Button>
      </div>

      <Modal
        open={isOpen}
        onOpenChange={(next) => {
          if (!isPending) setIsOpen(next);
        }}
        title={`Delete ${selectedCount} mute rule${pluralSuffix}`}
        description="Removes the selected rules from Mutelist. Existing muted findings will remain muted."
        size="md"
      >
        <form onSubmit={handleSubmit} className="flex flex-col gap-5">
          <div className="border-border-neutral-secondary bg-bg-neutral-tertiary rounded-xl border p-4">
            <p className="text-text-neutral-tertiary text-xs font-medium tracking-[0.08em] uppercase">
              Rules to delete
            </p>
            <ul className="text-text-neutral-primary mt-2 space-y-1 text-sm">
              {previewNames.map((name) => (
                <li key={name} className="truncate font-medium">
                  {name}
                </li>
              ))}
            </ul>
            {hiddenPreviewCount > 0 ? (
              <p className="text-text-neutral-tertiary mt-2 text-xs">
                {`+${hiddenPreviewCount} more rule${
                  hiddenPreviewCount === 1 ? "" : "s"
                }`}
              </p>
            ) : null}
            <p className="text-text-neutral-tertiary mt-3 text-xs">
              This action cannot be undone, but previously muted findings remain
              muted.
            </p>
          </div>

          <FormButtons
            onCancel={() => setIsOpen(false)}
            submitText={isPending ? "Deleting..." : `Delete ${selectedCount}`}
            isDisabled={isPending}
            submitColor="danger"
            rightIcon={isPending ? undefined : <Trash2 className="size-4" />}
          />
        </form>
      </Modal>
    </>
  );
}
