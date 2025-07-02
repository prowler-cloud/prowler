"use client";

import { Textarea } from "@nextui-org/react";
import { Dispatch, SetStateAction, useEffect, useRef, useState } from "react";
import { useFormState } from "react-dom";

import {
  createMutedFindingsConfig,
  deleteMutedFindingsConfig,
  updateMutedFindingsConfig,
} from "@/actions/processors";
import { DeleteIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { FormButtons } from "@/components/ui/form";
import {
  MutedFindingsConfigActionState,
  ProcessorData,
} from "@/types/processors";

interface MutedFindingsConfigFormProps {
  setIsOpen: Dispatch<SetStateAction<boolean>>;
  existingConfig?: ProcessorData;
  onConfigDeleted?: () => void | Promise<void>;
}

export const MutedFindingsConfigForm = ({
  setIsOpen,
  existingConfig,
  onConfigDeleted,
}: MutedFindingsConfigFormProps) => {
  const [state, formAction, isPending] = useFormState<
    MutedFindingsConfigActionState,
    FormData
  >(
    existingConfig ? updateMutedFindingsConfig : createMutedFindingsConfig,
    null,
  );
  const [configuration, setConfiguration] = useState(
    existingConfig?.attributes.configuration || "",
  );
  const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);
  const { toast } = useToast();

  useEffect(() => {
    if (state?.success) {
      toast({
        title: "Configuration saved successfully",
        description: state.success,
      });
      setIsOpen(false);
    } else if (state?.errors?.general) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: state.errors.general,
      });
    }
  }, [state, toast, setIsOpen]);

  const handleDeleteConfirm = async () => {
    if (!existingConfig) return;

    setIsDeleting(true);
    const formData = new FormData();
    formData.append("id", existingConfig.id);

    try {
      const result = await deleteMutedFindingsConfig(null, formData);

      if (result?.success) {
        toast({
          title: "Configuration deleted successfully",
          description: result.success,
        });
        onConfigDeleted?.();
        setIsOpen(false);
      } else if (result?.errors?.general) {
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: result.errors.general,
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: "Error deleting configuration. Please try again.",
      });
    } finally {
      setIsDeleting(false);
      setShowDeleteConfirmation(false);
    }
  };

  if (showDeleteConfirmation) {
    return (
      <div className="flex flex-col space-y-4">
        <h3 className="text-lg font-semibold text-default-700">
          Delete Muted Findings Configuration
        </h3>
        <p className="text-sm text-default-600">
          Are you sure you want to delete this configuration? This action cannot
          be undone.
        </p>

        <div className="flex w-full justify-center space-x-6">
          <CustomButton
            type="button"
            ariaLabel="Cancel"
            className="w-full bg-transparent"
            variant="faded"
            size="lg"
            onPress={() => setShowDeleteConfirmation(false)}
            isDisabled={isDeleting}
          >
            <span>Cancel</span>
          </CustomButton>

          <CustomButton
            type="button"
            ariaLabel="Delete"
            className="w-full"
            variant="solid"
            color="danger"
            size="lg"
            isLoading={isDeleting}
            startContent={!isDeleting && <DeleteIcon size={24} />}
            onPress={handleDeleteConfirm}
          >
            {isDeleting ? <>Deleting</> : <span>Delete</span>}
          </CustomButton>
        </div>
      </div>
    );
  }

  return (
    <form ref={formRef} action={formAction} className="flex flex-col space-y-4">
      {existingConfig && (
        <input type="hidden" name="id" value={existingConfig.id} />
      )}

      <div className="space-y-4">
        <div>
          <p className="mb-2 text-sm text-default-600">
            Configuring Muted Findings creates an Allowlist for future Findings.
          </p>
          <ul className="mb-4 list-disc pl-5 text-sm text-default-600">
            <li>
              These Findings will no longer appear in your dashboards and
              reports unless you select
              <strong> &quot;Show Muted Findings&quot;</strong> in the filters
              menu.
            </li>
            <li>
              <strong>Muted Findings will take effect on the next scan.</strong>
            </li>
            <li>
              You may modify your Muted Findings configuration at anytime on the
              Findings page.
            </li>
            <li>
              Learn more about configuring your Muted Findings here:{" "}
              <button
                type="button"
                className="text-primary underline hover:text-primary-600"
                onClick={() =>
                  window.open("https://docs.prowler.com/", "_blank")
                }
              >
                Allowlist Documentation
              </button>
            </li>
          </ul>
        </div>

        <div className="space-y-2">
          <label
            htmlFor="configuration"
            className="text-sm font-medium text-default-700"
          >
            Allowlist Configuration
          </label>
          <Textarea
            id="configuration"
            name="configuration"
            placeholder="Enter your YAML configuration..."
            variant="bordered"
            minRows={15}
            maxRows={20}
            value={configuration}
            onChange={(e) => setConfiguration(e.target.value)}
            isInvalid={!!state?.errors?.configuration}
            errorMessage={state?.errors?.configuration}
            classNames={{
              input: "font-mono text-sm",
            }}
          />
        </div>
      </div>

      <div className="flex flex-col space-y-4">
        <FormButtons
          setIsOpen={setIsOpen}
          submitText={existingConfig ? "Update" : "Save"}
        />

        {existingConfig && (
          <CustomButton
            type="button"
            ariaLabel="Delete Configuration"
            className="w-full"
            variant="bordered"
            color="danger"
            size="md"
            startContent={<DeleteIcon size={20} />}
            onPress={() => setShowDeleteConfirmation(true)}
            isDisabled={isPending}
          >
            Delete Configuration
          </CustomButton>
        )}
      </div>
    </form>
  );
};
