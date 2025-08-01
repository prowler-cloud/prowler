"use client";

import { Textarea } from "@nextui-org/react";
import { Dispatch, SetStateAction, useEffect, useState } from "react";
import { useFormState } from "react-dom";

import {
  createMutedFindingsConfig,
  deleteMutedFindingsConfig,
  getMutedFindingsConfig,
  updateMutedFindingsConfig,
} from "@/actions/processors";
import { DeleteIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { FormButtons } from "@/components/ui/form";
import { fontMono } from "@/config/fonts";
import { convertToYaml, parseYamlValidation } from "@/lib/yaml";
import {
  MutedFindingsConfigActionState,
  ProcessorData,
} from "@/types/processors";

interface MutedFindingsConfigFormProps {
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}

export const MutedFindingsConfigForm = ({
  setIsOpen,
}: MutedFindingsConfigFormProps) => {
  const [config, setConfig] = useState<ProcessorData | null>(null);
  const [configText, setConfigText] = useState("");
  const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [yamlValidation, setYamlValidation] = useState<{
    isValid: boolean;
    error?: string;
  }>({ isValid: true });
  const [hasUserStartedTyping, setHasUserStartedTyping] = useState(false);

  const [state, formAction, isPending] = useFormState<
    MutedFindingsConfigActionState,
    FormData
  >(config ? updateMutedFindingsConfig : createMutedFindingsConfig, null);

  const { toast } = useToast();

  useEffect(() => {
    getMutedFindingsConfig().then((result) => {
      setConfig(result || null);
      const yamlConfig = convertToYaml(result?.attributes.configuration || "");
      setConfigText(yamlConfig);
      setHasUserStartedTyping(false); // Reset when loading initial config
      if (yamlConfig) {
        setYamlValidation(parseYamlValidation(yamlConfig));
      }
    });
  }, []);

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
    } else if (state?.errors?.configuration) {
      // Reset typing state when there are new server errors
      setHasUserStartedTyping(false);
    }
  }, [state, toast, setIsOpen]);

  const handleConfigChange = (value: string) => {
    setConfigText(value);
    // Clear server errors when user starts typing
    setHasUserStartedTyping(true);
    // Validate YAML in real-time
    const validation = parseYamlValidation(value);
    setYamlValidation(validation);
  };

  const handleDelete = async () => {
    if (!config) return;

    setIsDeleting(true);
    const formData = new FormData();
    formData.append("id", config.id);

    try {
      const result = await deleteMutedFindingsConfig(null, formData);
      if (result?.success) {
        toast({
          title: "Configuration deleted successfully",
          description: result.success,
        });
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
          Delete Mutelist Configuration
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
            Cancel
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
            onPress={handleDelete}
          >
            {isDeleting ? "Deleting" : "Delete"}
          </CustomButton>
        </div>
      </div>
    );
  }

  return (
    <form action={formAction} className="flex flex-col space-y-4">
      {config && <input type="hidden" name="id" value={config.id} />}

      <div className="space-y-4">
        <div>
          <ul className="mb-4 list-disc pl-5 text-sm text-default-600">
            <li>
              <strong>
                This Mutelist configuration will take effect on the next scan.
              </strong>
            </li>
            <li>
              Mutelist configuration can be modified at anytime on the Providers
              and Scans pages.
            </li>
            <li>
              Learn more about configuring the Mutelist{" "}
              <CustomLink href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/mutelist/">
                here
              </CustomLink>
              .
            </li>
            <li>
              A default Mutelist is used, to exclude certain predefined
              resources, if no Mutelist is provided.
            </li>
          </ul>
        </div>

        <div className="space-y-2">
          <label
            htmlFor="configuration"
            className="text-sm font-medium text-default-700"
          >
            Mutelist Configuration
          </label>
          <div>
            <Textarea
              id="configuration"
              name="configuration"
              placeholder="Enter your YAML configuration..."
              variant="bordered"
              value={configText}
              onChange={(e) => handleConfigChange(e.target.value)}
              minRows={20}
              maxRows={20}
              isInvalid={
                (!hasUserStartedTyping && !!state?.errors?.configuration) ||
                !yamlValidation.isValid
              }
              errorMessage={
                (!hasUserStartedTyping && state?.errors?.configuration) ||
                (!yamlValidation.isValid ? yamlValidation.error : "")
              }
              classNames={{
                input: fontMono.className + " text-sm",
                base: "min-h-[400px]",
                errorMessage: "whitespace-pre-wrap",
              }}
            />
            {yamlValidation.isValid && configText && hasUserStartedTyping && (
              <div className="my-1 flex items-center px-1 text-tiny text-success">
                <span>Valid YAML format</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="flex flex-col space-y-4">
        <FormButtons
          setIsOpen={setIsOpen}
          submitText={config ? "Update" : "Save"}
          isDisabled={!yamlValidation.isValid || !configText.trim()}
        />

        {config && (
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
