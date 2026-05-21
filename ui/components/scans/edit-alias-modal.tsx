"use client";

import { Pencil } from "lucide-react";
import { useRouter } from "next/navigation";
import type { FormEvent } from "react";
import { useEffect, useState } from "react";

import { updateScan } from "@/actions/scans";
import { Field, FieldError, FieldLabel, Input } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { FormButtons } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";

interface EditAliasModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  scanId: string;
  currentAlias: string;
}

const ALIAS_MIN_LENGTH = 3;
const ALIAS_MAX_LENGTH = 32;

export function EditAliasModal({
  open,
  onOpenChange,
  scanId,
  currentAlias,
}: EditAliasModalProps) {
  const router = useRouter();
  const [alias, setAlias] = useState(currentAlias);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (open) {
      setAlias(currentAlias);
      setError(null);
    }
  }, [open, currentAlias]);

  const closeModal = () => {
    setError(null);
    onOpenChange(false);
  };

  const validate = (value: string): string | null => {
    if (value.length > 0 && value.length < ALIAS_MIN_LENGTH) {
      return `Alias must be empty or have at least ${ALIAS_MIN_LENGTH} characters.`;
    }
    if (value.length > ALIAS_MAX_LENGTH) {
      return `Alias must not exceed ${ALIAS_MAX_LENGTH} characters.`;
    }
    if (value === currentAlias) {
      return "The new alias must be different from the current one.";
    }
    return null;
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const trimmed = alias.trim();
    const validationError = validate(trimmed);
    if (validationError) {
      setError(validationError);
      return;
    }

    setSubmitting(true);
    setError(null);

    const formData = new FormData();
    formData.set("scanId", scanId);
    formData.set("scanName", trimmed);

    const result = await updateScan(formData);
    setSubmitting(false);

    if (result?.errors && result.errors.length > 0) {
      setError(String(result.errors[0]?.detail ?? "Failed to update alias."));
      return;
    }

    toast({
      title: "Alias updated",
      description: "The scan alias was updated successfully.",
    });
    closeModal();
    router.refresh();
  };

  return (
    <Modal
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) closeModal();
        else onOpenChange(true);
      }}
      title="Edit Alias"
      size="xl"
      className="gap-8"
    >
      <form onSubmit={submit} className="flex flex-col gap-8">
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
            value={alias}
            onChange={(event) => setAlias(event.target.value)}
            placeholder={currentAlias || "Enter scan alias"}
          />
        </Field>

        {error && <FieldError>{error}</FieldError>}

        <FormButtons
          onCancel={closeModal}
          submitText={submitting ? "Saving..." : "Save"}
          loadingText="Saving..."
          isDisabled={submitting}
        />
      </form>
    </Modal>
  );
}
