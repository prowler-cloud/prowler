import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SendToJiraModal } from "./send-to-jira-modal";

const {
  getJiraIntegrationsMock,
  getJiraIssueTypesMock,
  pollJiraDispatchTaskMock,
  sendFindingToJiraMock,
  sendJiraDispatchMock,
  toastMock,
} = vi.hoisted(() => ({
  getJiraIntegrationsMock: vi.fn(),
  getJiraIssueTypesMock: vi.fn(),
  pollJiraDispatchTaskMock: vi.fn(),
  sendFindingToJiraMock: vi.fn(),
  sendJiraDispatchMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/integrations/jira-dispatch", () => ({
  getJiraIntegrations: getJiraIntegrationsMock,
  getJiraIssueTypes: getJiraIssueTypesMock,
  pollJiraDispatchTask: pollJiraDispatchTaskMock,
  sendFindingToJira: sendFindingToJiraMock,
  sendJiraDispatch: sendJiraDispatchMock,
}));

vi.mock("@/components/shadcn/toast", () => ({
  toast: toastMock,
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
    pollJiraDispatchTaskMock.mockResolvedValue({
      success: true,
      message: "Finding successfully sent to Jira!",
    });
  });

  it("shows the grouped-vs-separate choice for a target batch with multiple Findings before dispatching", async () => {
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={vi.fn()}
        findingId="check-a"
        findingTitle="Check A"
        targetIds={["check-a"]}
        targetType="check_id"
        targetBatches={[
          {
            targetIds: ["check-a"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ]}
        defaultDispatchMode="grouped"
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
        findingId="finding-1"
        findingTitle="Finding 1"
        targetIds={["finding-1", "finding-2"]}
        targetType="finding_id"
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
        findingId="check-a"
        findingTitle="Check A"
        targetIds={["check-a"]}
        targetType="check_id"
        targetBatches={[
          {
            targetIds: ["check-a"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ]}
        defaultDispatchMode="grouped"
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
    expect(pollJiraDispatchTaskMock).toHaveBeenCalledWith("group-task");
    expect(pollJiraDispatchTaskMock).toHaveBeenCalledWith("finding-task");
  });

  it("shows a success toast after individual Finding dispatch succeeds", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingId="finding-1"
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
        findingId="check-a"
        findingTitle="Check A"
        targetIds={["check-a"]}
        targetType="check_id"
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

  it("keeps polling until a slow grouped Finding Group dispatch succeeds", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    sendJiraDispatchMock.mockResolvedValueOnce({
      success: true,
      taskId: "group-task",
      message: "Group started",
    });
    pollJiraDispatchTaskMock
      .mockResolvedValueOnce({
        success: false,
        error: "Task timeout",
      })
      .mockResolvedValueOnce({
        success: true,
        message: "Finding successfully sent to Jira!",
      });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingId="check-a"
        findingTitle="Check A"
        targetIds={["check-a"]}
        targetType="check_id"
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
      expect(pollJiraDispatchTaskMock).toHaveBeenCalledTimes(2),
    );
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
        findingId="check-a"
        findingTitle="Check A"
        targetBatches={[
          {
            targetIds: ["check-a"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ]}
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
    expect(toastMock).toHaveBeenCalledTimes(1);
  });

  it("shows an error toast when Jira dispatch polling reports partial failures", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    pollJiraDispatchTaskMock.mockResolvedValue({
      success: false,
      error: "Jira dispatch completed with 1 failed and 2 created issues.",
    });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingId="finding-1"
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
        variant: "destructive",
        title: "Error",
        description:
          "Jira dispatch completed with 1 failed and 2 created issues.",
      }),
    );
    expect(toastMock).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: "Success!" }),
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
    pollJiraDispatchTaskMock
      .mockResolvedValueOnce({
        success: true,
        message: "Finding successfully sent to Jira!",
      })
      .mockResolvedValueOnce({
        success: false,
        error: "Jira dispatch completed with 1 failed and 1 created issue.",
      });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingId="check-a"
        findingTitle="Check A"
        targetBatches={[
          {
            targetIds: ["check-a"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ]}
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
          "Finding successfully sent to Jira! Some Jira dispatches failed: Jira dispatch completed with 1 failed and 1 created issue.",
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
        findingId="check-a"
        findingTitle="Check A"
        targetBatches={[
          {
            targetIds: ["check-a"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ]}
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
      expect(pollJiraDispatchTaskMock).toHaveBeenCalledWith("group-task"),
    );
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        title: "Partial success",
        description:
          "Finding successfully sent to Jira! Some Jira dispatches failed: Failed to launch Finding batch.",
      }),
    );
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
    pollJiraDispatchTaskMock.mockResolvedValueOnce({
      success: false,
      error: "Jira dispatch completed with 1 failed issue.",
    });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        findingId="check-a"
        findingTitle="Check A"
        targetBatches={[
          {
            targetIds: ["check-a"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ]}
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
        variant: "destructive",
        title: "Error",
        description:
          "Jira dispatch completed with 1 failed issue. Failed to launch Finding batch.",
      }),
    );
  });
});
