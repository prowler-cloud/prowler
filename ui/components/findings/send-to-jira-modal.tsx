"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Send } from "lucide-react";
import { type Dispatch, type SetStateAction, useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  getJiraIntegrations,
  getJiraIssueTypes,
  pollJiraDispatchTask,
  sendFindingToJira,
  sendJiraDispatch,
} from "@/actions/integrations/jira-dispatch";
import { CustomBanner } from "@/components/shadcn/custom/custom-banner";
import { Form, FormField, FormMessage } from "@/components/shadcn/form";
import { FormButtons } from "@/components/shadcn/form/form-buttons";
import { Modal } from "@/components/shadcn/modal";
import {
  RadioGroup,
  RadioGroupItem,
} from "@/components/shadcn/radio-group/radio-group";
import { EnhancedMultiSelect } from "@/components/shadcn/select/enhanced-multi-select";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { toast } from "@/components/shadcn/toast";
import {
  IntegrationProps,
  JIRA_DISPATCH_MODE,
  JIRA_DISPATCH_TARGET,
  type JiraDispatchMode,
  type JiraDispatchTarget,
} from "@/types/integrations";

import {
  buildJiraDispatchChoiceCopy,
  JIRA_SELECTION_KIND,
} from "./send-to-jira-modal-copy";

interface JiraDispatchTargetBatch {
  targetIds: string[];
  targetType: JiraDispatchTarget;
  dispatchMode?: JiraDispatchMode;
}

interface SendToJiraModalBaseProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  findingId: string;
  findingTitle?: string;
  defaultDispatchMode?: JiraDispatchMode;
  canChooseGroupedDispatch?: boolean;
  isFindingGroupSelection?: boolean;
  selectedResourceCount?: number;
  description?: string;
}

interface SendToJiraSingleTargetProps extends SendToJiraModalBaseProps {
  targetIds?: never;
  targetType?: never;
  targetBatches?: never;
}

interface SendToJiraTargetListProps extends SendToJiraModalBaseProps {
  targetIds: string[];
  targetType: JiraDispatchTarget;
  targetBatches?: never;
}

interface SendToJiraBatchProps extends SendToJiraModalBaseProps {
  targetIds?: never;
  targetType?: never;
  targetBatches: JiraDispatchTargetBatch[];
}

type SendToJiraModalProps =
  | SendToJiraSingleTargetProps
  | SendToJiraTargetListProps
  | SendToJiraBatchProps;

const sendToJiraSchema = z.object({
  integration: z.string().min(1, "Please select a Jira integration"),
  project: z.string().min(1, "Please select a project"),
  issueType: z.string().min(1, "Please select an issue type"),
  dispatchMode: z.enum([
    JIRA_DISPATCH_MODE.GROUPED,
    JIRA_DISPATCH_MODE.INDIVIDUAL,
  ]),
});

type SendToJiraFormData = z.infer<typeof sendToJiraSchema>;

const JIRA_TASK_TIMEOUT_ERROR = "Task timeout";
const JIRA_TASK_POLL_ROUNDS = 15;

const pollJiraDispatchTaskUntilDone = async (taskId: string) => {
  for (let round = 0; round < JIRA_TASK_POLL_ROUNDS; round++) {
    const result = await pollJiraDispatchTask(taskId);
    if (result.success || result.error !== JIRA_TASK_TIMEOUT_ERROR) {
      return result;
    }
  }

  return {
    success: false,
    error: "The Jira dispatch task is taking too long. Try again later.",
  } as const;
};

export const SendToJiraModal = ({
  isOpen,
  onOpenChange,
  findingId,
  findingTitle,
  targetIds,
  targetType = JIRA_DISPATCH_TARGET.FINDING_ID,
  targetBatches,
  defaultDispatchMode = JIRA_DISPATCH_MODE.INDIVIDUAL,
  canChooseGroupedDispatch = false,
  isFindingGroupSelection = false,
  selectedResourceCount,
  description,
}: SendToJiraModalProps) => {
  const [integrations, setIntegrations] = useState<IntegrationProps[]>([]);
  const [isFetchingIntegrations, setIsFetchingIntegrations] = useState(false);
  const [fetchedIssueTypes, setFetchedIssueTypes] = useState<
    Record<string, string[]>
  >({});
  const [isFetchingIssueTypes, setIsFetchingIssueTypes] = useState(false);

  const form = useForm<SendToJiraFormData>({
    resolver: zodResolver(sendToJiraSchema),
    defaultValues: {
      integration: "",
      project: "",
      issueType: "",
      dispatchMode: defaultDispatchMode,
    },
  });

  const jiraTargetIds = targetIds?.length ? targetIds : [findingId];
  const jiraTargetBatches = targetBatches?.length
    ? targetBatches.filter((batch) => batch.targetIds.length > 0)
    : [
        {
          targetIds: jiraTargetIds,
          targetType,
        },
      ];
  const multiFindingTargetCount =
    jiraTargetBatches.find(
      (batch) =>
        batch.targetType === JIRA_DISPATCH_TARGET.FINDING_ID &&
        batch.targetIds.length > 1,
    )?.targetIds.length ?? 0;
  const jiraSelectedResourceCount =
    selectedResourceCount ?? jiraTargetIds.length;
  const hasMultipleFindingTargets = multiFindingTargetCount > 1;
  const shouldShowDispatchChoice =
    (canChooseGroupedDispatch || hasMultipleFindingTargets) &&
    (multiFindingTargetCount > 1 || jiraSelectedResourceCount > 1);
  const checkIdBatches = jiraTargetBatches.filter(
    (batch) => batch.targetType === JIRA_DISPATCH_TARGET.CHECK_ID,
  );
  const hasOnlySingleFindingGroupBatch =
    jiraTargetBatches.length === 1 &&
    checkIdBatches.length === 1 &&
    checkIdBatches[0].targetIds.length === 1;
  const isSelectedFindingGroupFlow =
    shouldShowDispatchChoice &&
    (isFindingGroupSelection || hasOnlySingleFindingGroupBatch);
  const jiraDispatchChoiceCopy = buildJiraDispatchChoiceCopy({
    selectedCount:
      multiFindingTargetCount > 1
        ? multiFindingTargetCount
        : jiraSelectedResourceCount,
    isSelectedFindingGroupFlow,
    selectionKind:
      multiFindingTargetCount > 1
        ? JIRA_SELECTION_KIND.FINDINGS
        : JIRA_SELECTION_KIND.RESOURCES,
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
      // Reset form and fetched data when modal closes
      form.reset();
      setFetchedIssueTypes({});
    }
  }, [isOpen, form]);

  useEffect(() => {
    if (isOpen) {
      form.setValue("dispatchMode", defaultDispatchMode);
    }
  }, [defaultDispatchMode, form, isOpen]);

  const handleSubmit = async (data: SendToJiraFormData) => {
    // Close modal immediately; continue processing in background
    onOpenChange(false);

    void (async () => {
      try {
        const taskIds: string[] = [];
        const launchErrors: string[] = [];

        for (const batch of jiraTargetBatches) {
          const batchDispatchMode = batch.dispatchMode ?? data.dispatchMode;
          const result =
            batch.targetIds.length === 1 &&
            batch.targetType === JIRA_DISPATCH_TARGET.FINDING_ID &&
            batchDispatchMode === JIRA_DISPATCH_MODE.INDIVIDUAL
              ? await sendFindingToJira(
                  data.integration,
                  batch.targetIds[0],
                  data.project,
                  data.issueType,
                )
              : await sendJiraDispatch({
                  integrationId: data.integration,
                  targetIds: batch.targetIds,
                  filter: batch.targetType,
                  projectKey: data.project,
                  issueType: data.issueType,
                  dispatchMode: batchDispatchMode,
                });

          if (!result.success) {
            launchErrors.push(result.error || "Failed to send to Jira");
            continue;
          }

          taskIds.push(result.taskId);
        }

        if (taskIds.length === 0 && launchErrors.length > 0) {
          throw new Error(launchErrors.join(" "));
        }

        // Poll for task completion and notify once
        const taskResults = await Promise.all(
          taskIds.map((taskId) => pollJiraDispatchTaskUntilDone(taskId)),
        );
        const errors = [
          ...taskResults
            .filter((taskResult) => !taskResult.success)
            .map(
              (taskResult) => taskResult.error || "Failed to create Jira issue",
            ),
          ...launchErrors,
        ];
        const warnings = taskResults.flatMap((taskResult) => {
          if (!taskResult.success || !taskResult.warning) return [];
          return [taskResult.warning];
        });

        if (errors.length > 0 || warnings.length > 0) {
          const successfulTask = taskResults.find(
            (taskResult) => taskResult.success,
          );
          if (successfulTask) {
            const failedMessages = [...warnings, ...errors].join(" ");
            toast({
              title: "Partial success",
              description: `${successfulTask.message || "Some Jira issues were created successfully."} Some Jira dispatches failed: ${failedMessages}`,
            });
            return;
          }

          throw new Error(errors.join(" "));
        }

        toast({
          title: "Success!",
          description:
            taskResults.find((taskResult) => taskResult.success)?.message ||
            "Finding sent to Jira successfully",
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

  const selectedProject = form.watch("project");

  const selectedIntegrationData = integrations.find(
    (i) => i.id === selectedIntegration,
  );

  const projects: Record<string, string> =
    selectedIntegrationData?.attributes.configuration.projects ??
    ({} as Record<string, string>);

  const projectEntries = Object.entries(projects);

  // Get issue types from config (new dict format), falling back to fetched data
  const configIssueTypes = selectedIntegrationData?.attributes.configuration
    .issue_types as Record<string, string[]> | undefined;
  const issueTypesFromConfig =
    configIssueTypes &&
    typeof configIssueTypes === "object" &&
    !Array.isArray(configIssueTypes)
      ? (configIssueTypes[selectedProject] ?? [])
      : [];
  const issueTypesForProject =
    issueTypesFromConfig.length > 0
      ? issueTypesFromConfig
      : (fetchedIssueTypes[selectedProject] ?? []);

  // Fetch issue types from API when project is selected but no types are available
  useEffect(() => {
    let ignore = false;

    if (
      selectedIntegration &&
      selectedProject &&
      issueTypesFromConfig.length === 0 &&
      !fetchedIssueTypes[selectedProject]
    ) {
      const fetchIssueTypes = async () => {
        setIsFetchingIssueTypes(true);
        try {
          const result = await getJiraIssueTypes(
            selectedIntegration,
            selectedProject,
          );
          if (ignore) return;
          if (result.success) {
            setFetchedIssueTypes((prev) => ({
              ...prev,
              [selectedProject]: result.issueTypes,
            }));
          } else {
            toast({
              variant: "destructive",
              title: "Failed to load issue types",
              description:
                result.error || "Unable to fetch issue types for this project",
            });
          }
        } finally {
          if (!ignore) setIsFetchingIssueTypes(false);
        }
      };

      fetchIssueTypes();
    }

    return () => {
      ignore = true;
    };
  }, [
    selectedIntegration,
    selectedProject,
    issueTypesFromConfig.length,
    fetchedIssueTypes,
  ]);

  const issueTypeOptions = issueTypesForProject.map((type) => ({
    value: type,
    label: type,
  }));

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
        description
          ? description
          : shouldShowDispatchChoice
            ? jiraDispatchChoiceCopy.description
            : findingTitle
              ? `Create a Jira issue for: "${findingTitle}"`
              : "Select integration, project and issue type to create a Jira issue"
      }
    >
      <Form {...form}>
        <form
          onSubmit={form.handleSubmit(handleSubmit)}
          className="flex flex-col gap-4"
        >
          {/* Loading skeleton for project selector */}
          {isFetchingIntegrations && (
            <div className="flex flex-col gap-1.5">
              <Skeleton className="h-3 w-16" />
              <Skeleton className="h-12 w-full rounded-md" />
            </div>
          )}

          {/* Integration Selection */}
          {!isFetchingIntegrations && integrations.length > 1 && (
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
                      form.setValue("issueType", "");
                      setFetchedIssueTypes({});
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
          {!isFetchingIntegrations &&
            selectedIntegration &&
            projectEntries.length > 0 && (
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
                        // Reset issue type when project changes
                        form.setValue("issueType", "");
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

          {/* Issue Type Selection */}
          {selectedProject && (
            <FormField
              control={form.control}
              name="issueType"
              render={({ field }) => (
                <div className="flex flex-col gap-1.5">
                  <label
                    htmlFor="jira-issue-type-select"
                    className="text-text-neutral-secondary text-xs font-light tracking-tight"
                  >
                    Issue Type
                  </label>
                  <EnhancedMultiSelect
                    id="jira-issue-type-select"
                    options={issueTypeOptions}
                    onValueChange={(values) => {
                      const selectedValue = values.at(-1) ?? "";
                      field.onChange(selectedValue);
                    }}
                    defaultValue={field.value ? [field.value] : []}
                    placeholder={
                      isFetchingIssueTypes
                        ? "Loading issue types..."
                        : "Select an issue type"
                    }
                    searchable={true}
                    emptyIndicator="No issue types found."
                    disabled={isFetchingIssueTypes}
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

          {shouldShowDispatchChoice && (
            <FormField
              control={form.control}
              name="dispatchMode"
              render={({ field }) => (
                <div className="flex flex-col gap-2">
                  <span className="text-text-neutral-secondary text-xs font-light tracking-tight">
                    Jira issue creation mode
                  </span>
                  <RadioGroup
                    value={field.value}
                    onValueChange={field.onChange}
                    className="gap-3"
                  >
                    <label className="border-border-neutral-secondary bg-bg-neutral-secondary flex cursor-pointer gap-3 rounded-md border p-3">
                      <RadioGroupItem
                        value={JIRA_DISPATCH_MODE.GROUPED}
                        aria-label="Create one Jira issue"
                      />
                      <span className="flex flex-col gap-1">
                        <span className="text-text-neutral-primary text-sm font-medium">
                          {jiraDispatchChoiceCopy.groupedTitle}
                        </span>
                        <span className="text-text-neutral-secondary text-xs">
                          {jiraDispatchChoiceCopy.groupedHelp}
                        </span>
                      </span>
                    </label>
                    <label className="border-border-neutral-secondary bg-bg-neutral-secondary flex cursor-pointer gap-3 rounded-md border p-3">
                      <RadioGroupItem
                        value={JIRA_DISPATCH_MODE.INDIVIDUAL}
                        aria-label="Create separate Jira issues"
                      />
                      <span className="flex flex-col gap-1">
                        <span className="text-text-neutral-primary text-sm font-medium">
                          Create separate Jira issues
                        </span>
                        <span className="text-text-neutral-secondary text-xs">
                          {jiraDispatchChoiceCopy.individualHelp}
                        </span>
                      </span>
                    </label>
                  </RadioGroup>
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
                isFetchingIssueTypes ||
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
