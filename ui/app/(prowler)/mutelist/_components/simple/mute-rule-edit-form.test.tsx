import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

const { updateMuteRuleMock, toastMock } = vi.hoisted(() => ({
  updateMuteRuleMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/mute-rules", () => ({
  updateMuteRule: updateMuteRuleMock,
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({
    toast: toastMock,
  }),
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

vi.mock("@/components/shadcn", () => ({
  Input: ({
    defaultValue,
    ...props
  }: React.InputHTMLAttributes<HTMLInputElement>) => (
    <input defaultValue={defaultValue} {...props} />
  ),
  Textarea: ({
    value,
    ...props
  }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) => (
    <textarea value={value} {...props} />
  ),
}));

vi.mock("@/components/ui/form/Label", () => ({
  Label: ({
    children,
    ...props
  }: React.LabelHTMLAttributes<HTMLLabelElement>) => (
    <label {...props}>{children}</label>
  ),
}));

import { MuteRuleEditForm } from "./mute-rule-edit-form";

const muteRule = {
  type: "mute-rules" as const,
  id: "mute-rule-1",
  attributes: {
    inserted_at: "2026-04-22T09:00:00Z",
    updated_at: "2026-04-22T09:05:00Z",
    name: "Ignore dev bucket",
    reason: "Existing reason",
    enabled: true,
    finding_uids: ["uid-1", "uid-2", "uid-3"],
  },
};

describe("MuteRuleEditForm", () => {
  it("submits successfully with a single toast and closes once", async () => {
    updateMuteRuleMock.mockResolvedValue({
      success: "Mute rule updated successfully!",
    });

    const user = userEvent.setup();
    const onSuccess = vi.fn();

    render(
      <MuteRuleEditForm
        muteRule={muteRule}
        onSuccess={onSuccess}
        onCancel={vi.fn()}
      />,
    );

    await user.clear(screen.getByLabelText("Reason"));
    await user.type(screen.getByLabelText("Reason"), "Updated reason");
    await user.click(screen.getByRole("button", { name: "Update" }));

    await waitFor(() => {
      expect(updateMuteRuleMock).toHaveBeenCalledTimes(1);
      expect(toastMock).toHaveBeenCalledTimes(1);
      expect(toastMock).toHaveBeenCalledWith({
        title: "Success",
        description: "Mute rule updated successfully!",
      });
      expect(onSuccess).toHaveBeenCalledTimes(1);
    });
  });

  it("shows the shared 500-char counter and clamps oversized input with a local error", () => {
    render(
      <MuteRuleEditForm
        muteRule={muteRule}
        onSuccess={vi.fn()}
        onCancel={vi.fn()}
      />,
    );

    const textarea = screen.getByLabelText("Reason");
    fireEvent.change(textarea, {
      target: { value: "a".repeat(501) },
    });

    expect(textarea).toHaveAttribute("maxLength", "500");
    expect(screen.getByText("500/500 characters")).toBeInTheDocument();
    expect(
      screen.getByText("Reason must be 500 characters or fewer"),
    ).toBeInTheDocument();
  });
});
