import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

const { createMuteRuleMock, toastMock } = vi.hoisted(() => ({
  createMuteRuleMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/mute-rules", () => ({
  createMuteRule: createMuteRuleMock,
}));

vi.mock("@/components/shadcn", () => ({
  Button: ({
    children,
    ...props
  }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button {...props}>{children}</button>
  ),
  Input: (props: React.InputHTMLAttributes<HTMLInputElement>) => (
    <input {...props} />
  ),
  Textarea: (props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) => (
    <textarea {...props} />
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

vi.mock("@/components/shadcn/skeleton/skeleton", () => ({
  Skeleton: ({ className }: { className?: string }) => (
    <div data-testid="skeleton" className={className} />
  ),
}));

vi.mock("@/components/shadcn/spinner/spinner", () => ({
  Spinner: ({ className }: { className?: string }) => (
    <div data-testid="spinner" className={className} />
  ),
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

import { MuteFindingsModal } from "./mute-findings-modal";

describe("MuteFindingsModal", () => {
  it("renders the ready state with accessible fields and descriptions", () => {
    render(
      <MuteFindingsModal
        isOpen
        onOpenChange={vi.fn()}
        findingIds={["finding-1", "finding-2"]}
      />,
    );

    expect(
      screen.getByText("You are about to mute", { exact: false }),
    ).toBeInTheDocument();
    expect(screen.getByText("Selected findings")).toBeInTheDocument();
    expect(screen.getByText("Rule details")).toBeInTheDocument();
    expect(screen.getByLabelText("Rule Name")).toBeInTheDocument();
    expect(screen.getByLabelText("Reason")).toBeInTheDocument();
    expect(
      screen.getByText("A descriptive name for this mute rule"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Explain why these findings are being muted"),
    ).toBeInTheDocument();
    expect(screen.getByText("0/500 characters")).toBeInTheDocument();
    expect(screen.getByLabelText("Reason")).toHaveAttribute("maxLength", "500");
  });

  it("renders the preparing state and blocks submission", () => {
    render(
      <MuteFindingsModal
        isOpen
        onOpenChange={vi.fn()}
        findingIds={[]}
        isPreparing
      />,
    );

    expect(
      screen.getByText("Preparing mute rule", { exact: false }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Preparing..." })).toBeDisabled();
    expect(screen.queryByLabelText("Rule Name")).not.toBeInTheDocument();
    expect(screen.queryByTestId("spinner")).not.toBeInTheDocument();
    expect(screen.getAllByTestId("skeleton").length).toBeGreaterThanOrEqual(8);
  });

  it("submits the form, shows the success toast, and closes the modal", async () => {
    createMuteRuleMock.mockResolvedValue({
      success: "Mute rule created successfully! Findings are now muted.",
    });

    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    const onComplete = vi.fn();

    render(
      <MuteFindingsModal
        isOpen
        onOpenChange={onOpenChange}
        findingIds={["finding-1", "finding-2"]}
        onComplete={onComplete}
        isBulkOperation
      />,
    );

    await user.type(screen.getByLabelText("Rule Name"), "Ignore dev buckets");
    await user.type(
      screen.getByLabelText("Reason"),
      "Expected failures in the development environment",
    );
    await user.click(screen.getByRole("button", { name: "Mute Findings" }));

    await waitFor(() => {
      expect(createMuteRuleMock).toHaveBeenCalledTimes(1);
      expect(toastMock).toHaveBeenCalledWith({
        title: "Success",
        description:
          "Mute rule created. It may take a few minutes for all findings to update.",
      });
      expect(onComplete).toHaveBeenCalledTimes(1);
      expect(onOpenChange).toHaveBeenCalledWith(false);
    });
  });

  it("clamps oversized reason input and shows a local validation error", () => {
    render(
      <MuteFindingsModal
        isOpen
        onOpenChange={vi.fn()}
        findingIds={["finding-1"]}
      />,
    );

    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "a".repeat(501) },
    });

    expect(screen.getByText("500/500 characters")).toBeInTheDocument();
    expect(
      screen.getByText("Reason must be 500 characters or fewer"),
    ).toBeInTheDocument();
  });
});
