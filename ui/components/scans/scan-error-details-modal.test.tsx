import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  ScanErrorDetailsModal,
  type ScanErrorDetailsState,
} from "./scan-error-details-modal";

vi.mock("@/components/shadcn/code-snippet/code-snippet", () => ({
  CodeSnippet: ({
    value,
    formatter,
    ariaLabel,
  }: {
    value: string;
    formatter?: (value: string) => string;
    ariaLabel?: string;
  }) => (
    <>
      <span>{formatter ? formatter(value) : value}</span>
      <button type="button" aria-label={ariaLabel ?? "Copy to clipboard"}>
        copy
      </button>
    </>
  ),
}));

const loadedState: ScanErrorDetailsState = {
  kind: "loaded",
  details: {
    type: "ValidationError",
    messages: ["Missing cloud credentials", "Retry scan setup"],
    module: "scan.runner",
    copyValue:
      "ErrorType: ValidationError\nError: Missing cloud credentials\nRetry scan setup",
  },
};

describe("ScanErrorDetailsModal", () => {
  it("renders nothing visible when closed", () => {
    render(
      <ScanErrorDetailsModal
        open={false}
        onOpenChange={vi.fn()}
        state={{ kind: "idle" }}
      />,
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("shows the loading placeholder while state is loading", () => {
    render(
      <ScanErrorDetailsModal
        open
        onOpenChange={vi.fn()}
        state={{ kind: "loading" }}
      />,
    );
    expect(screen.getByText(/loading error details/i)).toBeInTheDocument();
  });

  it("renders the error message when state is error", () => {
    render(
      <ScanErrorDetailsModal
        open
        onOpenChange={vi.fn()}
        state={{ kind: "error", message: "Task not found" }}
      />,
    );
    expect(screen.getByText("Task not found")).toBeInTheDocument();
  });

  it("renders error type, module and messages when loaded", () => {
    render(
      <ScanErrorDetailsModal open onOpenChange={vi.fn()} state={loadedState} />,
    );
    expect(screen.getByText("ValidationError")).toBeInTheDocument();
    expect(screen.getByText("scan.runner")).toBeInTheDocument();
    expect(screen.getByText(/Missing cloud credentials/)).toBeInTheDocument();
    expect(screen.getByText(/Retry scan setup/)).toBeInTheDocument();
  });

  it("shows the copy action only when state is loaded", () => {
    const { rerender } = render(
      <ScanErrorDetailsModal
        open
        onOpenChange={vi.fn()}
        state={{ kind: "loading" }}
      />,
    );
    expect(
      screen.queryByRole("button", { name: /copy error details/i }),
    ).not.toBeInTheDocument();

    rerender(
      <ScanErrorDetailsModal open onOpenChange={vi.fn()} state={loadedState} />,
    );
    expect(
      screen.getByRole("button", { name: /copy error details/i }),
    ).toBeInTheDocument();
  });
});
