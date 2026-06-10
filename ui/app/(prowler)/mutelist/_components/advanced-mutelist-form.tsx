"use client";

import { Trash2 } from "lucide-react";
import { useActionState, useEffect, useState } from "react";

import {
  createMutedFindingsConfig,
  deleteMutedFindingsConfig,
  getMutedFindingsConfig,
  updateMutedFindingsConfig,
} from "@/actions/processors";
import {
  Button,
  Card,
  FieldError,
  Skeleton,
  Textarea,
} from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { fontMono } from "@/config/fonts";
import { cn } from "@/lib/utils";
import {
  convertToYaml,
  defaultMutedFindingsConfig,
  parseYamlValidation,
} from "@/lib/yaml";
import {
  MutedFindingsConfigActionState,
  ProcessorData,
} from "@/types/processors";

export function AdvancedMutelistForm() {
  const [config, setConfig] = useState<ProcessorData | null>(null);
  const [configText, setConfigText] = useState("");
  const [showDeleteConfirmation, setShowDeleteConfirmation] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [yamlValidation, setYamlValidation] = useState<{
    isValid: boolean;
    error?: string;
  }>({ isValid: true });
  const [hasUserStartedTyping, setHasUserStartedTyping] = useState(false);

  // Unified action that decides to create or update based on ID presence
  const saveConfig = async (
    _prevState: MutedFindingsConfigActionState,
    formData: FormData,
  ): Promise<MutedFindingsConfigActionState> => {
    const id = formData.get("id");
    if (id) {
      return updateMutedFindingsConfig(_prevState, formData);
    }
    return createMutedFindingsConfig(_prevState, formData);
  };

  const [state, formAction, isPending] = useActionState<
    MutedFindingsConfigActionState,
    FormData
  >(saveConfig, null);

  const { toast } = useToast();

  useEffect(() => {
    getMutedFindingsConfig().then((result) => {
      setConfig(result || null);
      const yamlConfig = convertToYaml(result?.attributes.configuration || "");
      setConfigText(yamlConfig);
      setHasUserStartedTyping(false);
      if (yamlConfig) {
        setYamlValidation(parseYamlValidation(yamlConfig));
      }
      setIsLoading(false);
    });
  }, []);

  useEffect(() => {
    if (state?.success) {
      toast({
        title: "Configuration saved successfully",
        description: state.success,
      });
      // Reload config to get the created/updated data (shows Delete button)
      getMutedFindingsConfig().then((result) => {
        setConfig(result || null);
      });
    } else if (state?.errors?.general) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: state.errors.general,
      });
    } else if (state?.errors?.configuration) {
      setHasUserStartedTyping(false);
    }
  }, [state, toast]);

  const handleConfigChange = (value: string) => {
    setConfigText(value);
    setHasUserStartedTyping(true);
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
        setConfig(null);
        setConfigText("");
      } else if (result?.errors?.general) {
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: result.errors.general,
        });
      }
    } catch {
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

  const isConfigInvalid =
    (!hasUserStartedTyping && !!state?.errors?.configuration) ||
    !yamlValidation.isValid;
  const configErrorMessage =
    (!hasUserStartedTyping && state?.errors?.configuration) ||
    (!yamlValidation.isValid ? yamlValidation.error : "");

  if (isLoading) {
    return (
      <Card variant="base" className="p-6">
        <div className="flex flex-col gap-4">
          <Skeleton className="h-6 w-48" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-[400px] w-full" />
          <div className="flex w-full justify-end gap-4">
            <Skeleton className="h-10 w-24" />
            <Skeleton className="h-10 w-24" />
          </div>
        </div>
      </Card>
    );
  }

  return (
    <>
      {/* Delete Confirmation Modal */}
      <Modal
        open={showDeleteConfirmation}
        onOpenChange={setShowDeleteConfirmation}
        title="Delete Mutelist Configuration"
        size="md"
      >
        <div className="flex flex-col gap-4">
          <p className="text-text-neutral-secondary text-sm">
            Are you sure you want to delete this configuration? This action
            cannot be undone.
          </p>
          <div className="flex w-full justify-end gap-4">
            <Button
              type="button"
              variant="ghost"
              size="lg"
              onClick={() => setShowDeleteConfirmation(false)}
              disabled={isDeleting}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              size="lg"
              disabled={isDeleting}
              onClick={handleDelete}
            >
              <Trash2 className="size-4" />
              {isDeleting ? "Deleting..." : "Delete"}
            </Button>
          </div>
        </div>
      </Modal>

      <Card variant="base" className="p-6">
        <form action={formAction} className="flex flex-col gap-4">
          {config && <input type="hidden" name="id" value={config.id} />}

          <div className="flex flex-col gap-4">
            <div>
              <h3 className="text-text-neutral-secondary mb-2 text-lg font-semibold">
                Advanced Mutelist Configuration
              </h3>
              <ul className="text-text-neutral-secondary mb-4 list-disc pl-5 text-sm">
                <li>
                  <strong>
                    This Mutelist configuration will take effect on the next
                    scan.
                  </strong>
                </li>
                <li>
                  Use this for pattern-based muting with wildcards, regions, and
                  tags.
                </li>
                <li>
                  Learn more about configuring the Mutelist{" "}
                  <CustomLink
                    size="sm"
                    href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-mute-findings"
                  >
                    here
                  </CustomLink>
                  .
                </li>
                <li>
                  A default Mutelist is used to exclude certain predefined
                  resources if no Mutelist is provided.
                </li>
              </ul>
            </div>

            <div className="flex flex-col gap-2">
              <label
                htmlFor="configuration"
                className="text-text-neutral-secondary text-sm font-medium"
              >
                Mutelist Configuration (YAML)
              </label>
              <div>
                <Textarea
                  id="configuration"
                  name="configuration"
                  placeholder={defaultMutedFindingsConfig}
                  value={configText}
                  onChange={(e) => handleConfigChange(e.target.value)}
                  rows={20}
                  aria-invalid={isConfigInvalid}
                  className={cn(
                    fontMono.className,
                    "min-h-[400px] text-sm",
                    isConfigInvalid &&
                      "border-border-error focus:border-border-error focus:ring-border-error",
                  )}
                />
                {isConfigInvalid && configErrorMessage && (
                  <FieldError className="my-1 px-1 whitespace-pre-wrap">
                    {configErrorMessage}
                  </FieldError>
                )}
                {yamlValidation.isValid &&
                  configText &&
                  hasUserStartedTyping && (
                    <div className="text-text-success-primary my-1 flex items-center px-1 text-xs">
                      <span>Valid YAML format</span>
                    </div>
                  )}
              </div>
            </div>
          </div>

          <div className="flex w-full justify-end gap-4">
            {config && (
              <Button
                type="button"
                aria-label="Delete Configuration"
                variant="outline"
                size="lg"
                onClick={() => setShowDeleteConfirmation(true)}
                disabled={isPending || isDeleting}
              >
                <Trash2 className="size-4" />
                Delete
              </Button>
            )}
            <Button
              type="submit"
              size="lg"
              disabled={
                isPending || !yamlValidation.isValid || !configText.trim()
              }
            >
              {isPending ? "Saving..." : config ? "Update" : "Save"}
            </Button>
          </div>
        </form>
      </Card>
    </>
  );
}
