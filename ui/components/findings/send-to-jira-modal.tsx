"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Send } from "lucide-react";
import { type Dispatch, type SetStateAction, useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  getJiraIntegrations,
  pollJiraDispatchTask,
  sendFindingToJira,
} from "@/actions/integrations/jira-dispatch";
import { Modal } from "@/components/shadcn/modal";
import { EnhancedMultiSelect } from "@/components/shadcn/select/enhanced-multi-select";
import { useToast } from "@/components/ui";
import { CustomBanner } from "@/components/ui/custom/custom-banner";
import { Form, FormField, FormMessage } from "@/components/ui/form";
import { FormButtons } from "@/components/ui/form/form-buttons";
import { IntegrationProps } from "@/types/integrations";

interface SendToJiraModalProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  findingId: string;
  findingTitle?: string;
}

const sendToJiraSchema = z.object({
  integration: z.string().min(1, "Please select a Jira integration"),
  project: z.string().min(1, "Please select a project"),
  issueType: z.string().min(1, "Please select an issue type"),
});

type SendToJiraFormData = z.infer<typeof sendToJiraSchema>;

// The commented code is related to issue types, which are not required for the first implementation, but will be used in the future
export const SendToJiraModal = ({
  isOpen,
  onOpenChange,
  findingId,
  findingTitle,
}: SendToJiraModalProps) => {
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState<IntegrationProps[]>([]);
  const [isFetchingIntegrations, setIsFetchingIntegrations] = useState(false);

  const form = useForm<SendToJiraFormData>({
    resolver: zodResolver(sendToJiraSchema),
    defaultValues: {
      integration: "",
      project: "",
      // Default to Task while issue types are not fetched/required
      issueType: "Task",
    },
  });

  const selectedIntegration = form.watch("integration");

  const hasConnectedIntegration = integrations.some(
    (i) => i.attributes.connected === true,
  );

  const setOpenForFormButtons: Dispatch<SetStateAction<boolean>> = (value) => {
    const next = typeof value === "function" ? value(isOpen) : value;
    onOpenChange(next);
  };

  // Fetch Jira integrations when modal opens
  useEffect(() => {
    if (isOpen) {
      const fetchJiraIntegrations = async () => {
        setIsFetchingIntegrations(true);

        try {
          const result = await getJiraIntegrations();
          if (!result.success) {
            throw new Error(
              result.error || "Unable to fetch Jira integrations",
            );
          }
          setIntegrations(result.data);
          // Auto-select if only one integration
          if (result.data.length === 1) {
            form.setValue("integration", result.data[0].id);
          }
        } catch (error) {
          const message =
            error instanceof Error && error.message
              ? error.message
              : "Failed to load Jira integrations";
          toast({
            variant: "destructive",
            title: "Failed to load integrations",
            description: message,
          });
        } finally {
          setIsFetchingIntegrations(false);
        }
      };

      fetchJiraIntegrations();
    } else {
      // Reset form when modal closes
      form.reset();
    }
  }, [isOpen, form, toast]);

  const handleSubmit = async (data: SendToJiraFormData) => {
    // Close modal immediately; continue processing in background
    onOpenChange(false);

    void (async () => {
      try {
        // Send the finding to Jira
        const result = await sendFindingToJira(
          data.integration,
          findingId,
          data.project,
          data.issueType,
        );

        if (!result.success) {
          throw new Error(result.error || "Failed to send to Jira");
        }

        // Poll for task completion and notify once
        const taskResult = await pollJiraDispatchTask(result.taskId);

        if (!taskResult.success) {
          throw new Error(taskResult.error || "Failed to create Jira issue");
        }

        toast({
          title: "Success!",
          description:
            taskResult.message || "Finding sent to Jira successfully",
        });
      } catch (error) {
        const message =
          error instanceof Error && error.message
            ? error.message
            : "Failed to send finding to Jira";
        toast({
          variant: "destructive",
          title: "Error",
          description: message,
        });
      }
    })();
  };

  const selectedIntegrationData = integrations.find(
    (i) => i.id === selectedIntegration,
  );

  const projects: Record<string, string> =
    selectedIntegrationData?.attributes.configuration.projects ??
    ({} as Record<string, string>);

  const projectEntries = Object.entries(projects);

  const integrationOptions = integrations.map((integration) => ({
    value: integration.id,
    label: integration.attributes.configuration.domain || integration.id,
  }));

  const projectOptions = projectEntries.map(([key, name]) => ({
    value: key,
    label: `${key} - ${name}`,
  }));

  return (
    <Modal
      open={isOpen}
      onOpenChange={onOpenChange}
      title="Send Finding to Jira"
      description={
        findingTitle
          ? `Create a Jira issue for: "${findingTitle}"`
          : "Select integration, project and issue type to create a Jira issue"
      }
    >
      <Form {...form}>
        <form
          onSubmit={form.handleSubmit(handleSubmit)}
          className="flex flex-col gap-4"
        >
          {/* Integration Selection */}
          {integrations.length > 1 && (
            <FormField
              control={form.control}
              name="integration"
              render={({ field }) => (
                <div className="flex flex-col gap-1.5">
                  <label
                    htmlFor="jira-integration-select"
                    className="text-text-neutral-secondary text-xs font-light tracking-tight"
                  >
                    Jira Integration
                  </label>
                  <EnhancedMultiSelect
                    id="jira-integration-select"
                    options={integrationOptions}
                    onValueChange={(values) => {
                      const selectedValue = values.at(-1) ?? "";
                      field.onChange(selectedValue);
                      // Reset dependent fields
                      form.setValue("project", "");
                      form.setValue("issueType", "Task");
                    }}
                    defaultValue={field.value ? [field.value] : []}
                    placeholder="Select a Jira integration"
                    searchable={true}
                    emptyIndicator="No integrations found."
                    disabled={isFetchingIntegrations}
                    hideSelectAll={true}
                    maxCount={1}
                    closeOnSelect={true}
                    resetOnDefaultValueChange={true}
                  />
                  <FormMessage className="text-text-error text-xs" />
                </div>
              )}
            />
          )}

          {/* Project Selection */}
          {selectedIntegration && projectEntries.length > 0 && (
            <FormField
              control={form.control}
              name="project"
              render={({ field }) => (
                <div className="flex flex-col gap-1.5">
                  <label
                    htmlFor="jira-project-select"
                    className="text-text-neutral-secondary text-xs font-light tracking-tight"
                  >
                    Project
                  </label>
                  <EnhancedMultiSelect
                    id="jira-project-select"
                    options={projectOptions}
                    onValueChange={(values) => {
                      const selectedValue = values.at(-1) ?? "";
                      field.onChange(selectedValue);
                      // Keep issue type defaulting to Task when project changes
                      form.setValue("issueType", "Task");
                    }}
                    defaultValue={field.value ? [field.value] : []}
                    placeholder="Select a Jira project"
                    searchable={true}
                    emptyIndicator="No projects found."
                    hideSelectAll={true}
                    maxCount={1}
                    closeOnSelect={true}
                    resetOnDefaultValueChange={true}
                  />
                  <FormMessage className="text-text-error text-xs" />
                </div>
              )}
            />
          )}

          {/* No integrations or none connected message */}
          {!isFetchingIntegrations &&
          (integrations.length === 0 || !hasConnectedIntegration) ? (
            <CustomBanner
              title="Jira integration is not available"
              message="Please add or connect an integration first"
              buttonLabel="Configure"
              buttonLink="/integrations/jira"
            />
          ) : (
            <FormButtons
              setIsOpen={setOpenForFormButtons}
              onCancel={() => onOpenChange(false)}
              submitText="Send to Jira"
              cancelText="Cancel"
              loadingText="Sending..."
              isDisabled={
                !form.formState.isValid ||
                form.formState.isSubmitting ||
                isFetchingIntegrations ||
                integrations.length === 0 ||
                !hasConnectedIntegration
              }
              rightIcon={<Send size={20} />}
            />
          )}
        </form>
      </Form>
    </Modal>
  );
};
