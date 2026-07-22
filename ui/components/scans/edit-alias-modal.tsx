"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Pencil } from "lucide-react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { updateScan } from "@/actions/scans";
import { Field, FieldError, FieldLabel, Input } from "@/components/shadcn";
import { FormButtons } from "@/components/shadcn/form";
import { Modal } from "@/components/shadcn/modal";
import { toast } from "@/components/shadcn/toast";

import { scanAliasSchema } from "./scan-alias-validation";

const buildEditAliasSchema = (currentAlias: string) =>
  z.object({
    alias: scanAliasSchema.refine(
      (value) => value.trim() !== currentAlias.trim(),
      "The new alias must be different from the current one.",
    ),
  });

type EditAliasFormValues = { alias: string };

interface EditAliasModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  scanId: string;
  currentAlias: string;
}

interface EditAliasFormProps {
  scanId: string;
  currentAlias: string;
  onClose: () => void;
}

function EditAliasForm({ scanId, currentAlias, onClose }: EditAliasFormProps) {
  const router = useRouter();
  const form = useForm<EditAliasFormValues>({
    resolver: zodResolver(buildEditAliasSchema(currentAlias)),
    defaultValues: { alias: currentAlias },
  });

  const onSubmit = form.handleSubmit(async ({ alias }) => {
    const trimmed = alias.trim();
    const formData = new FormData();
    formData.set("scanId", scanId);
    formData.set("scanName", trimmed);

    const result = await updateScan(formData);

    if (result?.errors && result.errors.length > 0) {
      form.setError("alias", {
        message: String(result.errors[0]?.detail ?? "Failed to update alias."),
      });
      return;
    }

    toast({
      title: "Alias updated",
      description: "The scan alias was updated successfully.",
    });
    onClose();
    router.refresh();
  });

  const aliasError = form.formState.errors.alias?.message;
  const isSubmitting = form.formState.isSubmitting;

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-8">
      <div className="flex items-center gap-2">
        <Pencil className="text-text-neutral-secondary size-4" />
        <span className="text-text-neutral-secondary text-sm">
          Current alias:{" "}
          <span className="text-text-neutral-primary font-medium">
            {currentAlias || "Unnamed"}
          </span>
        </span>
      </div>

      <Field>
        <FieldLabel htmlFor="edit-alias-input">Alias</FieldLabel>
        <Input
          id="edit-alias-input"
          aria-label="Alias"
          placeholder={currentAlias || "Enter scan alias"}
          {...form.register("alias")}
        />
        {aliasError && <FieldError>{aliasError}</FieldError>}
      </Field>

      <FormButtons
        onCancel={onClose}
        submitText={isSubmitting ? "Saving..." : "Save"}
        loadingText="Saving..."
        isDisabled={isSubmitting}
      />
    </form>
  );
}

export function EditAliasModal({
  open,
  onOpenChange,
  scanId,
  currentAlias,
}: EditAliasModalProps) {
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Edit Alias"
      size="xl"
      className="gap-8"
    >
      <EditAliasForm
        scanId={scanId}
        currentAlias={currentAlias}
        onClose={() => onOpenChange(false)}
      />
    </Modal>
  );
}
