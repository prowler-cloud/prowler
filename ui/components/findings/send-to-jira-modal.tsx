"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Input, Select, type Selection, SelectItem } from "@nextui-org/react";
import { Search, Send } from "lucide-react";
import {
  type Dispatch,
  type SetStateAction,
  useEffect,
  useMemo,
  useState,
} from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  getJiraIntegrations,
  pollJiraDispatchTask,
  sendFindingToJira,
} from "@/actions/integrations/jira-dispatch";
import { JiraIcon } from "@/components/icons/services/IconServices";
import { useToast } from "@/components/ui";
import { CustomAlertModal } from "@/components/ui/custom";
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
  const [searchIssueTypeValue, setSearchIssueTypeValue] = useState("");

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
  const selectedProject = form.watch("project");

  const hasConnectedIntegration = useMemo(
    () => integrations.some((i) => i.attributes.connected === true),
    [integrations],
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
      fetchJiraIntegrations();
    } else {
      // Reset form when modal closes
      form.reset();
      setSearchProjectValue("");
      setSearchIssueTypeValue("");
    }
  }, [isOpen, form]);

  const fetchJiraIntegrations = async () => {
    setIsFetchingIntegrations(true);
    try {
      const result = await getJiraIntegrations();
      if (!result.success) {
        throw new Error(result.error || "Unable to fetch Jira integrations");
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
    selectedIntegrationData?.attributes.configuration.projects ||
    ({} as Record<string, string>);
  const issueTypes: string[] =
    selectedIntegrationData?.attributes.configuration.issue_types ||
    ([] as string[]);

  // Filter projects based on search
  const filteredProjects = useMemo(() => {
    const projectEntries = Object.entries(projects);
    if (!searchProjectValue) return projectEntries;

    const lowerSearch = searchProjectValue.toLowerCase();
    return projectEntries.filter(
      ([key, name]) =>
        key.toLowerCase().includes(lowerSearch) ||
        name.toLowerCase().includes(lowerSearch),
    );
  }, [projects, searchProjectValue]);

  // TODO: Uncomment this when issue types are fetched/required
  // Filter issue types based on search
  // const filteredIssueTypes = useMemo(() => {
  //   if (!searchIssueTypeValue) return issueTypes;

  //   const lowerSearch = searchIssueTypeValue.toLowerCase();
  //   return issueTypes.filter((type) =>
  //     type.toLowerCase().includes(lowerSearch),
  //   );
  // }, [issueTypes, searchIssueTypeValue]);

  return (
    <CustomAlertModal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      title="Send Finding to Jira"
      description={
        findingTitle
          ? `Create a Jira issue for: "${findingTitle}"`
          : "Select integration, project and issue type to create a Jira issue"
      }
    >
      <Form {...form}>
        <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-4">
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
                        setSearchIssueTypeValue("");
                      }}
                      variant="bordered"
                      labelPlacement="inside"
                      isDisabled={isFetchingIntegrations}
                      isInvalid={!!form.formState.errors.integration}
                      startContent={<JiraIcon size={16} />}
                      classNames={{
                        trigger: "min-h-12",
                        popoverContent: "dark:bg-gray-800",
                        label:
                          "tracking-tight font-light !text-default-500 text-xs !z-0",
                        value: "text-default-500 text-small dark:text-gray-300",
                      }}
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
                  <FormMessage className="text-xs text-system-error" />
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
                        setSearchIssueTypeValue("");
                      }}
                      variant="bordered"
                      labelPlacement="inside"
                      isInvalid={!!form.formState.errors.project}
                      classNames={{
                        trigger: "min-h-12",
                        popoverContent: "dark:bg-gray-800",
                        listboxWrapper: "max-h-[300px] dark:bg-gray-800",
                        label:
                          "tracking-tight font-light !text-default-500 text-xs !z-0",
                        value: "text-default-500 text-small dark:text-gray-300",
                      }}
                      listboxProps={{
                        topContent:
                          filteredProjects.length > 5 ? (
                            <div className="sticky top-0 z-10 bg-content1 py-2 dark:bg-gray-800">
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
                                    "border-default-200 bg-transparent hover:bg-default-100/50",
                                  input: "text-small",
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
                                  <span className="truncate text-small">
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
                  <FormMessage className="text-xs text-system-error" />
                </>
              )}
            />
          )}

          {/* Issue Type Selection - Enhanced Style */}
          {/* {selectedProject && issueTypes.length > 0 && (
            <FormField
              control={form.control}
              name="issueType"
              render={({ field }) => (
                <>
                  <FormControl>
                    <Select
                      label="Issue Type"
                      placeholder="Select an issue type"
                      selectedKeys={
                        field.value ? new Set([field.value]) : new Set()
                      }
                      onSelectionChange={(keys: Selection) => {
                        const value = getSelectedValue(keys);
                        field.onChange(value);
                      }}
                      variant="bordered"
                      labelPlacement="inside"
                      isInvalid={!!form.formState.errors.issueType}
                      classNames={{
                        trigger: "min-h-12",
                        popoverContent: "dark:bg-gray-800",
                        listboxWrapper: "max-h-[300px] dark:bg-gray-800",
                        label:
                          "tracking-tight font-light !text-default-500 text-xs !z-0",
                        value: "text-default-500 text-small dark:text-gray-300",
                      }}
                      listboxProps={{
                        topContent:
                          filteredIssueTypes.length > 5 ? (
                            <div className="sticky top-0 z-10 bg-content1 py-2 dark:bg-gray-800">
                              <Input
                                isClearable
                                placeholder="Search issue types..."
                                size="sm"
                                variant="bordered"
                                startContent={<Search size={16} />}
                                value={searchIssueTypeValue}
                                onValueChange={setSearchIssueTypeValue}
                                onClear={() => setSearchIssueTypeValue("")}
                                classNames={{
                                  inputWrapper:
                                    "border-default-200 bg-transparent hover:bg-default-100/50",
                                  input: "text-small",
                                }}
                              />
                            </div>
                          ) : null,
                      }}
                    >
                      {filteredIssueTypes.map((type) => (
                        <SelectItem key={type} textValue={type}>
                          <div className="flex items-center py-1">
                            <span className="text-small">{type}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </Select>
                  </FormControl>
                  <FormMessage className="text-xs text-system-error" />
                </>
              )}
            />
          )} */}

          {/* No integrations or none connected message */}
          {!isFetchingIntegrations &&
            (integrations.length === 0 || !hasConnectedIntegration) && (
              <CustomBanner
                title="Jira integration is not available"
                message="Please add or connect an integration first"
                buttonLabel="Configure"
                buttonLink="/integrations/jira"
              />
            )}

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
        </form>
      </Form>
    </CustomAlertModal>
  );
};
