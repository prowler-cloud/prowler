"use client";

import { Textarea } from "@nextui-org/react";
import yaml from "js-yaml";
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
import { FormButtons } from "@/components/ui/form";
import {
  MutedFindingsConfigActionState,
  ProcessorData,
} from "@/types/processors";

interface MutedFindingsConfigFormProps {
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}

const convertToYaml = (config: string | object): string => {
  if (!config) return "";

  try {
    // If it's already an object, convert directly to YAML
    if (typeof config === "object") {
      return yaml.dump(config, { indent: 2 });
    }

    // If it's a string, try to parse as JSON first
    try {
      const jsonConfig = JSON.parse(config);
      return yaml.dump(jsonConfig, { indent: 2 });
    } catch {
      // If it's not JSON, assume it's already YAML
      return config;
    }
  } catch (error) {
    console.error("Error converting config to YAML:", error);
    return config.toString();
  }
};

export const MutedFindingsConfigForm = ({
  setIsOpen,
}: MutedFindingsConfigFormProps) => {
  const [config, setConfig] = useState<ProcessorData | null>(null);
  const [configText, setConfigText] = useState("");
  const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  const [state, formAction, isPending] = useFormState<
    MutedFindingsConfigActionState,
    FormData
  >(config ? updateMutedFindingsConfig : createMutedFindingsConfig, null);

  const { toast } = useToast();

  useEffect(() => {
    getMutedFindingsConfig().then((result) => {
      setConfig(result || null);
      setConfigText(convertToYaml(result?.attributes.configuration || ""));
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
    }
  }, [state, toast, setIsOpen]);

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
            value={configText}
            onChange={(e) => setConfigText(e.target.value)}
            minRows={15}
            maxRows={20}
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
          submitText={config ? "Update" : "Save"}
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
