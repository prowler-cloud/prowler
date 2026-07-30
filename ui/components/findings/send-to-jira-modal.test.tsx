import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ComponentProps } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createJiraBatchSelection } from "@/lib/jira-dispatch-selection";
import { JIRA_DISPATCH_MODE, JIRA_DISPATCH_TARGET } from "@/types/integrations";

import { SendToJiraModal } from "./send-to-jira-modal";

interface ToastActionMockProps extends ComponentProps<"button"> {
  altText: string;
}

const {
  executeJiraDispatchBatchesMock,
  getJiraIntegrationsMock,
  getJiraIssueTypesMock,
  toastMock,
} = vi.hoisted(() => ({
  executeJiraDispatchBatchesMock: vi.fn(),
  getJiraIntegrationsMock: vi.fn(),
  getJiraIssueTypesMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/integrations/jira-dispatch", () => ({
  getJiraIntegrations: getJiraIntegrationsMock,
  getJiraIssueTypes: getJiraIssueTypesMock,
}));

vi.mock("@/lib/jira-dispatch-execution", () => ({
  executeJiraDispatchBatches: executeJiraDispatchBatchesMock,
}));

vi.mock("@/components/shadcn/toast", () => ({
  toast: toastMock,
  ToastAction: ({
    altText: _altText,
    children,
    ...props
  }: ToastActionMockProps) => <button {...props}>{children}</button>,
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

const selection = createJiraBatchSelection([
  {
    targetIds: ["check-a"],
    targetType: JIRA_DISPATCH_TARGET.CHECK_ID,
    dispatchMode: JIRA_DISPATCH_MODE.GROUPED,
  },
  {
    targetIds: ["finding-1", "finding-2"],
    targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
  },
])!;

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
    executeJiraDispatchBatchesMock.mockResolvedValue({
      startedTaskCount: 2,
      successfulTaskCount: 2,
      successfulIssueCount: 3,
      successMessage: "3 Jira issues were created or updated successfully.",
      warnings: [],
      errors: [],
    });
  });

  it("renders the dispatch choice and custom mixed-selection description", async () => {
    // Given / When
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={vi.fn()}
        selection={selection}
        defaultDispatchMode={JIRA_DISPATCH_MODE.GROUPED}
        description="Create Jira issues for 1 Group and 2 Findings."
      />,
    );

    // Then
    expect(screen.getByText("Jira issue creation mode")).toBeInTheDocument();
    expect(
      screen.getByText("Create one Jira issue for all selected Findings"),
    ).toBeInTheDocument();
    expect(screen.getByText("Create separate Jira issues")).toBeInTheDocument();
    expect(
      screen.getByText("Create Jira issues for 1 Group and 2 Findings."),
    ).toBeInTheDocument();
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
  });

  it("delegates mixed dispatch execution with the selected settings", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        selection={selection}
        defaultDispatchMode={JIRA_DISPATCH_MODE.GROUPED}
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
    await waitFor(() =>
      expect(executeJiraDispatchBatchesMock).toHaveBeenCalledWith(
        [
          {
            targetIds: ["check-a"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ],
        {
          integrationId: "jira-1",
          projectKey: "SEC",
          issueType: "Task",
          dispatchMode: "individual",
        },
      ),
    );
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("retries only the failed Jira dispatch batch", async () => {
    // Given
    const user = userEvent.setup();
    const retryBatch = {
      targetIds: ["finding-2"],
      targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
      dispatchMode: JIRA_DISPATCH_MODE.INDIVIDUAL,
    } as const;
    executeJiraDispatchBatchesMock
      .mockResolvedValueOnce({
        startedTaskCount: 1,
        successfulTaskCount: 1,
        successfulIssueCount: 1,
        successMessage: "1 Jira issue was created successfully.",
        warnings: ["1 Jira issue failed."],
        errors: [],
        retryBatch,
      })
      .mockResolvedValueOnce({
        startedTaskCount: 1,
        successfulTaskCount: 1,
        successfulIssueCount: 1,
        successMessage: "1 Jira issue was created successfully.",
        warnings: [],
        errors: [],
      });
    const onOpenChange = vi.fn();
    const { rerender } = render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        selection={selection}
        defaultDispatchMode={JIRA_DISPATCH_MODE.GROUPED}
      />,
    );
    await waitFor(() => expect(getJiraIntegrationsMock).toHaveBeenCalled());
    await user.click(
      screen.getByRole("button", { name: "Select a Jira project" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Select an issue type" }),
    );
    await user.click(screen.getByRole("button", { name: "Send to Jira" }));
    await waitFor(() =>
      expect(executeJiraDispatchBatchesMock).toHaveBeenCalledTimes(1),
    );
    const partialToast = toastMock.mock.calls.find(
      ([toast]) => toast.title === "Partial success",
    )?.[0];
    rerender(
      <SendToJiraModal
        isOpen={false}
        onOpenChange={onOpenChange}
        selection={selection}
        defaultDispatchMode={JIRA_DISPATCH_MODE.GROUPED}
      />,
    );
    render(partialToast.action);

    // When
    await user.click(screen.getByRole("button", { name: "Retry failed" }));

    // Then
    await waitFor(() =>
      expect(executeJiraDispatchBatchesMock).toHaveBeenNthCalledWith(
        2,
        [retryBatch],
        {
          integrationId: "jira-1",
          projectKey: "SEC",
          issueType: "Task",
          dispatchMode: JIRA_DISPATCH_MODE.GROUPED,
        },
      ),
    );
  });

  it("closes the modal before navigating to Jira configuration", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    getJiraIntegrationsMock.mockResolvedValueOnce({
      success: true,
      data: [],
    });
    render(
      <SendToJiraModal
        isOpen
        onOpenChange={onOpenChange}
        selection={selection}
      />,
    );
    const configureLink = await screen.findByRole("link", {
      name: "Configure",
    });

    // When
    await user.click(configureLink);

    // Then
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
