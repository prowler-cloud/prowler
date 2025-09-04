"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Input, Select, SelectItem, type Selection } from "@nextui-org/react";
import { Search, Send } from "lucide-react";
import { useEffect, useMemo, useState, type Dispatch, type SetStateAction } from "react";
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
import { Form, FormControl, FormField, FormMessage } from "@/components/ui/form";
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
      issueType: "",
    },
  });

  const selectedIntegration = form.watch("integration");
  const selectedProject = form.watch("project");

  const getSelectedValue = (keys: Selection): string => {
    if (keys === "all") return "";
    const first = Array.from(keys)[0];
    return first != null ? String(first) : "";
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
      if (result.success) {
        setIntegrations(result.data);
        // Auto-select if only one integration
        if (result.data.length === 1) {
          form.setValue("integration", result.data[0].id);
        }
      } else {
        toast({
          variant: "destructive",
          title: "Failed to load integrations",
          description: result.error || "Unable to fetch Jira integrations",
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to load Jira integrations",
      });
    } finally {
      setIsFetchingIntegrations(false);
    }
  };

  const handleSubmit = async (data: SendToJiraFormData) => {
    try {
      // Send the finding to Jira
      const result = await sendFindingToJira(
        data.integration,
        findingId,
        data.project,
        data.issueType,
      );

      if (result.success) {
        // Show initial success message
        toast({
          title: "Sending to Jira...",
          description: "Creating issue in Jira. Please wait...",
        });

        // Poll for task completion
        const taskResult = await pollJiraDispatchTask(result.taskId);

        if (taskResult.success) {
          toast({
            title: "Success!",
            description: taskResult.message || "Finding sent to Jira successfully",
          });

          // Close the modal
          onOpenChange(false);
        } else {
          toast({
            variant: "destructive",
            title: "Failed to create Jira issue",
            description: taskResult.error || "An error occurred",
          });
        }
      } else {
        toast({
          variant: "destructive",
          title: "Failed to send to Jira",
          description: result.error || "An error occurred",
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to send finding to Jira",
      });
    }
  };

  const selectedIntegrationData = integrations.find(
    (i) => i.id === selectedIntegration,
  );

  const projects: Record<string, string> =
    selectedIntegrationData?.attributes.configuration.projects || ({} as Record<string, string>);
  const issueTypes: string[] =
    selectedIntegrationData?.attributes.configuration.issue_types || ([] as string[]);

  // Filter projects based on search
  const filteredProjects = useMemo(() => {
    const projectEntries = Object.entries(projects);
    if (!searchProjectValue) return projectEntries;
    
    const lowerSearch = searchProjectValue.toLowerCase();
    return projectEntries.filter(([key, name]) => 
      key.toLowerCase().includes(lowerSearch) || 
      name.toLowerCase().includes(lowerSearch)
    );
  }, [projects, searchProjectValue]);

  // Filter issue types based on search
  const filteredIssueTypes = useMemo(() => {
    if (!searchIssueTypeValue) return issueTypes;
    
    const lowerSearch = searchIssueTypeValue.toLowerCase();
    return issueTypes.filter(type => 
      type.toLowerCase().includes(lowerSearch)
    );
  }, [issueTypes, searchIssueTypeValue]);

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
                      selectedKeys={field.value ? new Set([field.value]) : new Set()}
                      onSelectionChange={(keys: Selection) => {
                        const value = getSelectedValue(keys);
                        field.onChange(value);
                        // Reset dependent fields
                        form.setValue("project", "");
                        form.setValue("issueType", "");
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
                        label: "tracking-tight font-light !text-default-500 text-xs !z-0",
                        value: "text-default-500 text-small dark:text-gray-300",
                      }}
                    >
                      {integrations.map((integration) => (
                        <SelectItem
                          key={integration.id}
                          textValue={integration.attributes.configuration.domain}
                        >
                          <div className="flex items-center gap-2">
                            <JiraIcon size={16} />
                            <span>{integration.attributes.configuration.domain}</span>
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
                      selectedKeys={field.value ? new Set([field.value]) : new Set()}
                      onSelectionChange={(keys: Selection) => {
                        const value = getSelectedValue(keys);
                        field.onChange(value);
                        // Reset issue type when project changes
                        form.setValue("issueType", "");
                        setSearchIssueTypeValue("");
                      }}
                      variant="bordered"
                      labelPlacement="inside"
                      isInvalid={!!form.formState.errors.project}
                      classNames={{
                        trigger: "min-h-12",
                        popoverContent: "dark:bg-gray-800",
                        listboxWrapper: "max-h-[300px] dark:bg-gray-800",
                        label: "tracking-tight font-light !text-default-500 text-xs !z-0",
                        value: "text-default-500 text-small dark:text-gray-300",
                      }}
                      listboxProps={{
                        topContent: filteredProjects.length > 5 ? (
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
                                inputWrapper: "border-default-200 bg-transparent hover:bg-default-100/50",
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
                                  <span className="font-semibold text-small">{key}</span>
                                  <span className="text-tiny text-default-500">-</span>
                                  <span className="truncate text-small">{name}</span>
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
          {selectedProject && issueTypes.length > 0 && (
            <FormField
              control={form.control}
              name="issueType"
              render={({ field }) => (
                <>
                  <FormControl>
                    <Select
                      label="Issue Type"
                      placeholder="Select an issue type"
                      selectedKeys={field.value ? new Set([field.value]) : new Set()}
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
                        label: "tracking-tight font-light !text-default-500 text-xs !z-0",
                        value: "text-default-500 text-small dark:text-gray-300",
                      }}
                      listboxProps={{
                        topContent: filteredIssueTypes.length > 5 ? (
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
                                inputWrapper: "border-default-200 bg-transparent hover:bg-default-100/50",
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
          )}

          {/* No integrations message */}
          {!isFetchingIntegrations && integrations.length === 0 && (
            <div className="rounded-lg border border-warning-200 bg-warning-50 p-4 dark:border-warning-800 dark:bg-warning-900/20">
              <p className="text-sm text-warning-800 dark:text-warning-200">
                No Jira integrations found. Please configure a Jira integration first.
              </p>
            </div>
          )}

          {/* Action Buttons using FormButtons */}
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
              integrations.length === 0
            }
            rightIcon={<Send size={20} />}
          />
        </form>
      </Form>
    </CustomAlertModal>
  );
};
