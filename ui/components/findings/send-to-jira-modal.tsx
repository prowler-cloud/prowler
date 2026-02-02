"use client";

import { Input } from "@heroui/input";
import { Select, SelectItem } from "@heroui/select";
import { zodResolver } from "@hookform/resolvers/zod";
import type { Selection } from "@react-types/shared";
import { Search, Send } from "lucide-react";
import { type Dispatch, type SetStateAction, useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  getJiraIntegrations,
  pollJiraDispatchTask,
  sendFindingToJira,
} from "@/actions/integrations/jira-dispatch";
import { JiraIcon } from "@/components/icons/services/IconServices";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { CustomBanner } from "@/components/ui/custom/custom-banner";
import {
  Form,
  FormControl,
  FormField,
  FormMessage,
} from "@/components/ui/form";
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

const selectorClassNames = {
  trigger: "min-h-12",
  popoverContent: "bg-bg-neutral-secondary",
  listboxWrapper: "max-h-[300px] bg-bg-neutral-secondary",
  listbox: "gap-0",
  label: "tracking-tight font-light !text-text-neutral-secondary text-xs z-0!",
  value: "text-text-neutral-secondary text-small",
};

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
  const [searchProjectValue, setSearchProjectValue] = useState("");
  // const [searchIssueTypeValue, setSearchIssueTypeValue] = useState("");

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
  // const selectedProject = form.watch("project");

  const hasConnectedIntegration = integrations.some(
    (i) => i.attributes.connected === true,
  );

  const getSelectedValue = (keys: Selection): string => {
    if (keys === "all") return "";
    const first = Array.from(keys)[0];
    return first !== null ? String(first) : "";
  };

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
      setSearchProjectValue("");
      // setSearchIssueTypeValue("");
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
  const shouldShowProjectSearch = projectEntries.length > 5;
  // const issueTypes: string[] =
  //   selectedIntegrationData?.attributes.configuration.issue_types ||
  //   ([] as string[]);

  // Filter projects based on search
  const filteredProjects = (() => {
    if (!searchProjectValue) return projectEntries;

    const lowerSearch = searchProjectValue.toLowerCase();
    return projectEntries.filter(
      ([key, name]) =>
        key.toLowerCase().includes(lowerSearch) ||
        name.toLowerCase().includes(lowerSearch),
    );
  })();

  // Filter issue types based on search
  // const filteredIssueTypes = useMemo(() => {
  //   if (!searchIssueTypeValue) return issueTypes;

  //   const lowerSearch = searchIssueTypeValue.toLowerCase();
  //   return issueTypes.filter((type) =>
  //     type.toLowerCase().includes(lowerSearch),
  //   );
  // }, [issueTypes, searchIssueTypeValue]);

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
                <>
                  <FormControl>
                    <Select
                      label="Jira Integration"
                      placeholder="Select a Jira integration"
                      selectedKeys={
                        field.value ? new Set([field.value]) : new Set()
                      }
                      onSelectionChange={(keys: Selection) => {
                        const value = getSelectedValue(keys);
                        field.onChange(value);
                        // Reset dependent fields
                        form.setValue("project", "");
                        // Keep issue type defaulting to Task
                        form.setValue("issueType", "Task");
                        setSearchProjectValue("");
                        // setSearchIssueTypeValue("");
                      }}
                      variant="bordered"
                      labelPlacement="inside"
                      isDisabled={isFetchingIntegrations}
                      isInvalid={!!form.formState.errors.integration}
                      startContent={<JiraIcon size={16} />}
                      classNames={selectorClassNames}
                    >
                      {integrations.map((integration) => (
                        <SelectItem
                          key={integration.id}
                          textValue={
                            integration.attributes.configuration.domain
                          }
                        >
                          <div className="flex items-center gap-2">
                            <JiraIcon size={16} />
                            <span>
                              {integration.attributes.configuration.domain}
                            </span>
                          </div>
                        </SelectItem>
                      ))}
                    </Select>
                  </FormControl>
                  <FormMessage className="text-text-error text-xs" />
                </>
              )}
            />
          )}

          {/* Project Selection - Enhanced Style */}
          {selectedIntegration && Object.keys(projects).length > 0 && (
            <FormField
              control={form.control}
              name="project"
              render={({ field }) => (
                <>
                  <FormControl>
                    <Select
                      label="Project"
                      placeholder="Select a Jira project"
                      selectedKeys={
                        field.value ? new Set([field.value]) : new Set()
                      }
                      onSelectionChange={(keys: Selection) => {
                        const value = getSelectedValue(keys);
                        field.onChange(value);
                        // Keep issue type defaulting to Task when project changes
                        form.setValue("issueType", "Task");
                        // setSearchIssueTypeValue("");
                      }}
                      variant="bordered"
                      labelPlacement="inside"
                      isInvalid={!!form.formState.errors.project}
                      classNames={selectorClassNames}
                      listboxProps={{
                        topContent: shouldShowProjectSearch ? (
                          <div className="sticky top-0 z-10 py-2">
                            <Input
                              isClearable
                              placeholder="Search projects..."
                              size="sm"
                              variant="bordered"
                              startContent={<Search size={16} />}
                              value={searchProjectValue}
                              onValueChange={setSearchProjectValue}
                              onClear={() => setSearchProjectValue("")}
                              classNames={{
                                inputWrapper:
                                  "border-border-input-primary bg-bg-input-primary hover:bg-bg-neutral-secondary",
                                input: "text-small",
                                clearButton: "text-default-400",
                              }}
                            />
                          </div>
                        ) : null,
                      }}
                    >
                      {filteredProjects.map(([key, name]) => (
                        <SelectItem key={key} textValue={`${key} - ${name}`}>
                          <div className="flex w-full items-center justify-between py-1">
                            <div className="flex min-w-0 flex-1 items-center gap-3">
                              <div className="min-w-0 flex-1">
                                <div className="flex items-center gap-2">
                                  <span className="text-small font-semibold">
                                    {key}
                                  </span>
                                  <span className="text-tiny text-default-500">
                                    -
                                  </span>
                                  <span className="text-small truncate">
                                    {name}
                                  </span>
                                </div>
                              </div>
                            </div>
                          </div>
                        </SelectItem>
                      ))}
                    </Select>
                  </FormControl>
                  <FormMessage className="text-text-error text-xs" />
                </>
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
