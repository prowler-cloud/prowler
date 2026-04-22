import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

const { bulkDeleteMuteRulesMock, toastMock } = vi.hoisted(() => ({
  bulkDeleteMuteRulesMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/mute-rules", () => ({
  bulkDeleteMuteRules: bulkDeleteMuteRulesMock,
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({
    toast: toastMock,
  }),
}));

vi.mock("@/components/shadcn", () => ({
  Button: ({
    children,
    ...props
  }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button {...props}>{children}</button>
  ),
}));

vi.mock("@/components/shadcn/modal", () => ({
  Modal: ({
    children,
    open,
    title,
  }: {
    children: ReactNode;
    open: boolean;
    title?: string;
  }) =>
    open ? (
      <div role="dialog" aria-label={title}>
        {children}
      </div>
    ) : null,
}));

vi.mock("@/components/ui/form", () => ({
  FormButtons: ({
    onCancel,
    submitText = "Save",
    isDisabled,
  }: {
    onCancel?: () => void;
    submitText?: string;
    isDisabled?: boolean;
  }) => (
    <div>
      <button type="button" onClick={onCancel}>
        Cancel
      </button>
      <button type="submit" disabled={isDisabled}>
        {submitText}
      </button>
    </div>
  ),
}));

import { FloatingBulkDeleteButton } from "./floating-bulk-delete-button";
import type { MuteRuleTableData } from "./mute-rule-target-previews";

const buildRule = (id: string, name: string): MuteRuleTableData => ({
  type: "mute-rules",
  id,
  attributes: {
    inserted_at: "2026-04-22T09:00:00Z",
    updated_at: "2026-04-22T09:05:00Z",
    name,
    reason: "Some reason",
    enabled: true,
    finding_uids: ["uid-1"],
  },
  targetLabels: ["Finding label"],
  targetSummaryLabel: "Finding label",
  hiddenTargetCount: 0,
});

describe("FloatingBulkDeleteButton", () => {
  it("renders the floating trigger with the selected count", () => {
    render(
      <FloatingBulkDeleteButton
        selectedCount={3}
        selectedRules={[
          buildRule("id-1", "Rule 1"),
          buildRule("id-2", "Rule 2"),
          buildRule("id-3", "Rule 3"),
        ]}
        onComplete={vi.fn()}
      />,
    );

    expect(
      screen.getByRole("button", { name: "Delete 3 rules" }),
    ).toBeInTheDocument();
  });

  it("uses singular copy when only one rule is selected", () => {
    render(
      <FloatingBulkDeleteButton
        selectedCount={1}
        selectedRules={[buildRule("id-1", "Rule 1")]}
        onComplete={vi.fn()}
      />,
    );

    expect(
      screen.getByRole("button", { name: "Delete 1 rule" }),
    ).toBeInTheDocument();
  });

  it("opens a confirmation modal listing the rule names", async () => {
    const user = userEvent.setup();

    render(
      <FloatingBulkDeleteButton
        selectedCount={2}
        selectedRules={[
          buildRule("id-1", "First rule"),
          buildRule("id-2", "Second rule"),
        ]}
        onComplete={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Delete 2 rules" }));

    const dialog = screen.getByRole("dialog", { name: "Delete 2 mute rules" });
    expect(dialog).toBeInTheDocument();
    expect(screen.getByText("First rule")).toBeInTheDocument();
    expect(screen.getByText("Second rule")).toBeInTheDocument();
  });

  it("truncates the preview list when more than five rules are selected", async () => {
    const user = userEvent.setup();

    render(
      <FloatingBulkDeleteButton
        selectedCount={7}
        selectedRules={Array.from({ length: 7 }, (_, index) =>
          buildRule(`id-${index}`, `Rule ${index}`),
        )}
        onComplete={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Delete 7 rules" }));

    expect(screen.getByText("+2 more rules")).toBeInTheDocument();
  });

  it("submits the bulk delete action and invokes onComplete", async () => {
    bulkDeleteMuteRulesMock.mockResolvedValue({
      success: "Deleted 2 mute rules successfully!",
    });

    const user = userEvent.setup();
    const onComplete = vi.fn();

    render(
      <FloatingBulkDeleteButton
        selectedCount={2}
        selectedRules={[
          buildRule("id-1", "First rule"),
          buildRule("id-2", "Second rule"),
        ]}
        onComplete={onComplete}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Delete 2 rules" }));
    await user.click(screen.getByRole("button", { name: "Delete 2" }));

    await waitFor(() => {
      expect(bulkDeleteMuteRulesMock).toHaveBeenCalledTimes(1);
    });

    const [, formData] = bulkDeleteMuteRulesMock.mock.calls[0];
    expect(JSON.parse(formData.get("ids") as string)).toEqual(["id-1", "id-2"]);

    expect(toastMock).toHaveBeenCalledWith({
      title: "Success",
      description: "Deleted 2 mute rules successfully!",
    });
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  it("shows a destructive toast when the action returns an error", async () => {
    bulkDeleteMuteRulesMock.mockResolvedValue({
      errors: { general: "Backend is unreachable" },
    });

    const user = userEvent.setup();
    const onComplete = vi.fn();

    render(
      <FloatingBulkDeleteButton
        selectedCount={1}
        selectedRules={[buildRule("id-1", "Rule 1")]}
        onComplete={onComplete}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Delete 1 rule" }));
    await user.click(screen.getByRole("button", { name: "Delete 1" }));

    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith({
        variant: "destructive",
        title: "Error",
        description: "Backend is unreachable",
      });
    });
    expect(onComplete).not.toHaveBeenCalled();
  });

  it("cancel closes the modal without calling the action", async () => {
    const user = userEvent.setup();

    render(
      <FloatingBulkDeleteButton
        selectedCount={1}
        selectedRules={[buildRule("id-1", "Rule 1")]}
        onComplete={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Delete 1 rule" }));
    expect(
      screen.getByRole("dialog", { name: "Delete 1 mute rule" }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(
      screen.queryByRole("dialog", { name: "Delete 1 mute rule" }),
    ).not.toBeInTheDocument();
    expect(bulkDeleteMuteRulesMock).not.toHaveBeenCalled();
  });
});
