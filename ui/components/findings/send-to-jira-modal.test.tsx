import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ComponentProps } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  createJiraBatchSelection,
  createJiraTargetSelection,
} from "@/lib/jira-dispatch-selection";
import {
  JIRA_DISPATCH_MODE,
  JIRA_DISPATCH_TARGET,
  type JiraDispatchTarget,
} from "@/types/integrations";

import { SendToJiraModal } from "./send-to-jira-modal";

const targetSelection = (targetIds: string[], targetType: JiraDispatchTarget) =>
  createJiraTargetSelection(targetIds, targetType)!;

const batchSelection = (
  batches: Parameters<typeof createJiraBatchSelection>[0],
) => createJiraBatchSelection(batches)!;

const {
  getJiraIntegrationsMock,
  getJiraIssueTypesMock,
  sendFindingToJiraMock,
  sendJiraDispatchMock,
  trackAndPollTaskMock,
  toastMock,
} = vi.hoisted(() => ({
  getJiraIntegrationsMock: vi.fn(),
  getJiraIssueTypesMock: vi.fn(),
  sendFindingToJiraMock: vi.fn(),
  sendJiraDispatchMock: vi.fn(),
  trackAndPollTaskMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/integrations/jira-dispatch", () => ({
  getJiraIntegrations: getJiraIntegrationsMock,
  getJiraIssueTypes: getJiraIssueTypesMock,
  sendFindingToJira: sendFindingToJiraMock,
  sendJiraDispatch: sendJiraDispatchMock,
}));

vi.mock("@/components/shadcn/toast", () => ({
  toast: toastMock,
  ToastAction: ({ children, ...props }: ComponentProps<"button">) => (
    <button {...props}>{children}</button>
  ),
}));

vi.mock("@/store/task-watcher/store", () => ({
  TASK_WATCHER_STATUS: {
    PENDING: "pending",
    READY: "ready",
    ERROR: "error",
  },
  trackAndPollTask: trackAndPollTaskMock,
}));

vi.mock("@/components/shadcn/select/enhanced-multi-select", () => ({
  EnhancedMultiSelect: ({
    options,
    onValueChange,
    placeholder,
    disabled,
  }: {
    options: { value: string; label: string }[];
    onValueChange: (values: string[]) => void;
    placeholder: string;
    disabled?: boolean;
  }) => (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onValueChange([options[0]?.value ?? ""])}
    >
      {placeholder}
    </button>
  ),
}));

describe("SendToJiraModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getJiraIntegrationsMock.mockResolvedValue({
      success: true,
      data: [
        {
          type: "integrations",
          id: "jira-1",
          attributes: {
            inserted_at: "2026-01-01T00:00:00Z",
            updated_at: "2026-01-01T00:00:00Z",
            enabled: true,
            connected: true,
            connection_last_checked_at: null,
            integration_type: "jira",
            configuration: {
              domain: "example.atlassian.net",
              projects: { SEC: "Security" },
              issue_types: { SEC: ["Task"] },
            },
          },
          links: { self: "/integrations/jira-1" },
        },
      ],
    });
    getJiraIssueTypesMock.mockResolvedValue({ success: true, issueTypes: [] });
    sendFindingToJiraMock.mockResolvedValue({
      success: true,
      taskId: "task-1",
      message: "Started",
    });
    sendJiraDispatchMock.mockResolvedValue({
      success: true,
      taskId: "task-1",
      message: "Started",
    });
    trackAndPollTaskMock.mockResolvedValue({
      status: "ready",
      result: { created_count: 1, failed_count: 0 },
    });
  });

  it("shows the grouped-vs-separate choice for a target batch with multiple Findings before dispatching", async () => {
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={vi.fn()}
        findingTitle="Check A"
        selection={batchSelection([
          {
            targetIds: ["check-a"],
            targetType: JIRA_DISPATCH_TARGET.CHECK_ID,
            dispatchMode: JIRA_DISPATCH_MODE.GROUPED,
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
          },
        ])}
        defaultDispatchMode={JIRA_DISPATCH_MODE.GROUPED}
        selectedResourceCount={1}
        description="Create Jira issues for 1 Group and 2 Findings."
      />,
    );

    expect(screen.getByText("Jira issue creation mode")).toBeInTheDocument();
    expect(
      screen.getByText("Create one Jira issue for all selected Findings"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(
        "Create one Jira issue for all selected Findings in this Finding Group",
      ),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText("Create Jira issues for 1 Group and 2 Findings."),
    ).toBeInTheDocument();
    expect(screen.getByText("Create separate Jira issues")).toBeInTheDocument();
    expect(sendFindingToJiraMock).not.toHaveBeenCalled();
    expect(sendJiraDispatchMock).not.toHaveBeenCalled();
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
  });

  it("uses neutral Findings copy for ordinary multi-Finding selections", async () => {
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={vi.fn()}
        findingTitle="Finding 1"
        selection={targetSelection(
          ["finding-1", "finding-2"],
          JIRA_DISPATCH_TARGET.FINDING_ID,
        )}
        defaultDispatchMode="grouped"
        canChooseGroupedDispatch
      />,
    );

    expect(screen.getByText("Jira issue creation mode")).toBeInTheDocument();
    expect(
      screen.getByText("Create one Jira issue for all selected Findings"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(
        "Create one Jira issue for all selected Findings in this Finding Group",
      ),
    ).not.toBeInTheDocument();
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
  });

  it("submits mixed Group and Finding batches with the correct dispatch filters and modes", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    sendJiraDispatchMock
      .mockResolvedValueOnce({
        success: true,
        taskId: "group-task",
        message: "Group started",
      })
      .mockResolvedValueOnce({
        success: true,
        taskId: "finding-task",
        message: "Findings started",
      });

    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingTitle="Check A"
        selection={batchSelection([
          {
            targetIds: ["check-a"],
            targetType: JIRA_DISPATCH_TARGET.CHECK_ID,
            dispatchMode: JIRA_DISPATCH_MODE.GROUPED,
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
          },
        ])}
        defaultDispatchMode={JIRA_DISPATCH_MODE.GROUPED}
        selectedResourceCount={1}
        description="Create Jira issues for 1 Group and 2 Findings."
      />,
    );

    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
    await user.click(
      screen.getByRole("button", { name: "Select a Jira project" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Select an issue type" }),
    );
    await user.click(
      screen.getByRole("radio", { name: "Create separate Jira issues" }),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    await waitFor(() => expect(sendJiraDispatchMock).toHaveBeenCalledTimes(2));
    expect(sendFindingToJiraMock).not.toHaveBeenCalled();
    expect(sendJiraDispatchMock).toHaveBeenNthCalledWith(1, {
      integrationId: "jira-1",
      targetIds: ["check-a"],
      filter: "check_id",
      projectKey: "SEC",
      issueType: "Task",
      dispatchMode: "grouped",
    });
    expect(sendJiraDispatchMock).toHaveBeenNthCalledWith(2, {
      integrationId: "jira-1",
      targetIds: ["finding-1", "finding-2"],
      filter: "finding_id",
      projectKey: "SEC",
      issueType: "Task",
      dispatchMode: "individual",
    });
    expect(trackAndPollTaskMock).toHaveBeenCalledWith(
      expect.objectContaining({ taskId: "group-task", notifyHandler: false }),
    );
    expect(trackAndPollTaskMock).toHaveBeenCalledWith(
      expect.objectContaining({ taskId: "finding-task", notifyHandler: false }),
    );
  });

  it("shows a success toast after individual Finding dispatch succeeds", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        selection={targetSelection(
          ["finding-1"],
          JIRA_DISPATCH_TARGET.FINDING_ID,
        )}
        findingTitle="Finding 1"
      />,
    );
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
    await user.click(
      screen.getByRole("button", { name: "Select a Jira project" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Select an issue type" }),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        title: "Success!",
        description: "Finding successfully sent to Jira!",
      }),
    );
    expect(sendFindingToJiraMock).toHaveBeenCalledWith(
      "jira-1",
      "finding-1",
      "SEC",
      "Task",
    );
  });

  it("shows a success toast after grouped Finding Group dispatch succeeds", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    sendJiraDispatchMock.mockResolvedValueOnce({
      success: true,
      taskId: "group-task",
      message: "Group started",
    });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingTitle="Check A"
        selection={targetSelection(["check-a"], JIRA_DISPATCH_TARGET.CHECK_ID)}
        defaultDispatchMode="grouped"
        selectedResourceCount={1}
      />,
    );
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
    await user.click(
      screen.getByRole("button", { name: "Select a Jira project" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Select an issue type" }),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        title: "Success!",
        description: "Finding successfully sent to Jira!",
      }),
    );
    expect(sendJiraDispatchMock).toHaveBeenCalledWith({
      integrationId: "jira-1",
      targetIds: ["check-a"],
      filter: "check_id",
      projectKey: "SEC",
      issueType: "Task",
      dispatchMode: "grouped",
    });
  });

  it("delegates grouped Finding Group task tracking to the shared watcher", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    sendJiraDispatchMock.mockResolvedValueOnce({
      success: true,
      taskId: "group-task",
      message: "Group started",
    });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingTitle="Check A"
        selection={targetSelection(["check-a"], JIRA_DISPATCH_TARGET.CHECK_ID)}
        defaultDispatchMode="grouped"
        selectedResourceCount={1}
      />,
    );
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
    await user.click(
      screen.getByRole("button", { name: "Select a Jira project" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Select an issue type" }),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    await waitFor(() => expect(trackAndPollTaskMock).toHaveBeenCalledOnce());
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        title: "Success!",
        description: "Finding successfully sent to Jira!",
      }),
    );
  });

  it("shows one success toast after mixed Group and Finding batches all succeed", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    sendJiraDispatchMock
      .mockResolvedValueOnce({
        success: true,
        taskId: "group-task",
        message: "Group started",
      })
      .mockResolvedValueOnce({
        success: true,
        taskId: "finding-task",
        message: "Findings started",
      });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingTitle="Check A"
        selection={batchSelection([
          {
            targetIds: ["check-a"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ])}
        defaultDispatchMode="grouped"
        selectedResourceCount={1}
      />,
    );
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
    await user.click(
      screen.getByRole("button", { name: "Select a Jira project" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Select an issue type" }),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        title: "Success!",
        description: "2 Jira issues were created or updated successfully.",
      }),
    );
    expect(toastMock).toHaveBeenCalledTimes(1);
  });

  it("shows a partial success toast when a task reports created and failed issues", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    trackAndPollTaskMock.mockResolvedValue({
      status: "ready",
      result: { created_count: 2, failed_count: 1 },
    });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        selection={targetSelection(
          ["finding-1"],
          JIRA_DISPATCH_TARGET.FINDING_ID,
        )}
        findingTitle="Finding 1"
      />,
    );
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());

    // When
    await user.click(
      screen.getByRole("button", { name: "Select a Jira project" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Select an issue type" }),
    );
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        title: "Partial success",
        description:
          "2 Jira issues were created or updated successfully. Some Jira dispatches failed: Jira dispatch completed with 1 failed and 2 created/updated issues.",
      }),
    );
    expect(toastMock).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: "Success!" }),
    );
  });

  it("retries only failed Findings after a partial task result", async () => {
    // Given
    const user = userEvent.setup();
    trackAndPollTaskMock.mockResolvedValueOnce({
      status: "ready",
      result: {
        created_count: 1,
        failed_count: 1,
        failed_finding_ids: ["finding-2"],
        error: "Jira rejected one Finding.",
      },
    });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={vi.fn()}
        selection={targetSelection(
          ["finding-1", "finding-2"],
          JIRA_DISPATCH_TARGET.FINDING_ID,
        )}
      />,
    );
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
    await user.click(
      screen.getByRole("button", { name: "Select a Jira project" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Select an issue type" }),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    await waitFor(() => expect(trackAndPollTaskMock).toHaveBeenCalled());
    const partialToast = toastMock.mock.calls.find(
      ([toast]) => toast.title === "Partial success",
    )?.[0];
    expect(partialToast?.action).toBeDefined();

    await partialToast.action.props.onClick();

    expect(sendFindingToJiraMock).toHaveBeenLastCalledWith(
      "jira-1",
      "finding-2",
      "SEC",
      "Task",
    );
  });

  it("shows a partial success toast when one mixed dispatch batch fails after another succeeds", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    sendJiraDispatchMock
      .mockResolvedValueOnce({
        success: true,
        taskId: "group-task",
        message: "Group started",
      })
      .mockResolvedValueOnce({
        success: true,
        taskId: "finding-task",
        message: "Findings started",
      });
    trackAndPollTaskMock
      .mockResolvedValueOnce({
        status: "ready",
        result: { created_count: 1, failed_count: 0 },
      })
      .mockResolvedValueOnce({
        status: "ready",
        result: { created_count: 0, failed_count: 1 },
      });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingTitle="Check A"
        selection={batchSelection([
          {
            targetIds: ["check-a"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ])}
        defaultDispatchMode="grouped"
        selectedResourceCount={1}
      />,
    );
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
    await user.click(
      screen.getByRole("button", { name: "Select a Jira project" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Select an issue type" }),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        title: "Partial success",
        description:
          "Finding successfully sent to Jira! Some Jira dispatches failed: Jira dispatch completed with 1 failed and 0 created/updated issues.",
      }),
    );
    expect(toastMock).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: "Success!" }),
    );
  });

  it("polls started tasks when a later mixed dispatch batch fails to launch", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    sendJiraDispatchMock
      .mockResolvedValueOnce({
        success: true,
        taskId: "group-task",
        message: "Group started",
      })
      .mockResolvedValueOnce({
        success: false,
        error: "Failed to launch Finding batch.",
      });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingTitle="Check A"
        selection={batchSelection([
          {
            targetIds: ["check-a"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ])}
        defaultDispatchMode="grouped"
        selectedResourceCount={1}
      />,
    );
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
    await user.click(
      screen.getByRole("button", { name: "Select a Jira project" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Select an issue type" }),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    await waitFor(() =>
      expect(trackAndPollTaskMock).toHaveBeenCalledWith(
        expect.objectContaining({ taskId: "group-task" }),
      ),
    );
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Partial success",
          description:
            "Finding successfully sent to Jira! Some Jira dispatches failed: Failed to launch Finding batch.",
        }),
      ),
    );
    const partialToast = toastMock.mock.calls.find(
      ([toast]) => toast.title === "Partial success",
    )?.[0];
    expect(partialToast?.action).toBeUndefined();
  });

  it("reports polling and launch failures together for mixed dispatches", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    sendJiraDispatchMock
      .mockResolvedValueOnce({
        success: true,
        taskId: "group-task",
        message: "Group started",
      })
      .mockResolvedValueOnce({
        success: false,
        error: "Failed to launch Finding batch.",
      });
    trackAndPollTaskMock.mockResolvedValueOnce({
      status: "error",
      error: "Jira dispatch completed with 1 failed issue.",
    });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingTitle="Check A"
        selection={batchSelection([
          {
            targetIds: ["check-a"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ])}
        defaultDispatchMode="grouped"
        selectedResourceCount={1}
      />,
    );
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
    await user.click(
      screen.getByRole("button", { name: "Select a Jira project" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Select an issue type" }),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          title: "Error",
          description:
            "Jira dispatch completed with 1 failed issue. Failed to launch Finding batch.",
        }),
      ),
    );
  });
});
