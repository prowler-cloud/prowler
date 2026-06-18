import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ScanErrorDetails } from "@/actions/task/task.adapter";

import { ScanErrorDetailsView } from "./scan-error-details-view";

vi.mock("@/components/ui/code-snippet/code-snippet", () => ({
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

const details: ScanErrorDetails = {
  type: "ValidationError",
  messages: ["Missing cloud credentials", "Retry scan setup"],
  module: "scan.runner",
  copyValue:
    "ErrorType: ValidationError\nError: Missing cloud credentials\nRetry scan setup",
};

describe("ScanErrorDetailsView", () => {
  it("renders error type, module and joined messages", () => {
    render(<ScanErrorDetailsView details={details} />);

    expect(screen.getByText("Error Type")).toBeInTheDocument();
    expect(screen.getByText("ValidationError")).toBeInTheDocument();
    expect(screen.getByText("Module")).toBeInTheDocument();
    expect(screen.getByText("scan.runner")).toBeInTheDocument();
    expect(screen.getByText(/Missing cloud credentials/)).toBeInTheDocument();
    expect(screen.getByText(/Retry scan setup/)).toBeInTheDocument();
  });

  it("omits the module field when not provided", () => {
    render(
      <ScanErrorDetailsView details={{ ...details, module: undefined }} />,
    );
    expect(screen.queryByText("Module")).not.toBeInTheDocument();
  });

  it("uses the provided copy aria label", () => {
    render(
      <ScanErrorDetailsView details={details} copyAriaLabel="Copy custom" />,
    );
    expect(
      screen.getByRole("button", { name: /copy custom/i }),
    ).toBeInTheDocument();
  });

  it("defaults the copy aria label to 'Copy error details'", () => {
    render(<ScanErrorDetailsView details={details} />);
    expect(
      screen.getByRole("button", { name: /copy error details/i }),
    ).toBeInTheDocument();
  });
});
