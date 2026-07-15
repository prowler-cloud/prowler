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

vi.mock("@/components/shadcn", () => ({
  useToast: () => ({ toast: toastMock }),
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
      screen.getByText(
        "Create one Jira issue for all selected Findings in this Finding Group",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Create separate Jira issues")).toBeInTheDocument();
    expect(sendFindingToJiraMock).not.toHaveBeenCalled();
    expect(sendJiraDispatchMock).not.toHaveBeenCalled();
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
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
  });
});
