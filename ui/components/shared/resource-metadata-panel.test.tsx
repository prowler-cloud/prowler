import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { ResourceMetadataPanel } from "./resource-metadata-panel";

vi.mock("@/components/shadcn/card/card", () => ({
  Card: ({ children, variant }: { children: ReactNode; variant?: string }) => (
    <div data-slot="card" data-variant={variant}>
      {children}
    </div>
  ),
}));

vi.mock("@/components/shared/query-code-editor", () => ({
  QUERY_EDITOR_LANGUAGE: {
    JSON: "json",
  },
  QueryCodeEditor: ({
    ariaLabel,
    value,
    copyValue,
  }: {
    ariaLabel: string;
    value: string;
    copyValue?: string;
  }) => (
    <div
      data-testid="query-code-editor"
      data-aria-label={ariaLabel}
      data-value={value}
      data-copy-value={copyValue}
    />
  ),
}));

const EMPTY_STATE = "No metadata available for this resource.";

describe("ResourceMetadataPanel", () => {
  it("renders only the details card when just details are present", () => {
    render(
      <ResourceMetadataPanel metadata={null} details="Some resource details" />,
    );

    expect(screen.getByText("Details:")).toBeInTheDocument();
    expect(screen.getByText("Some resource details")).toBeInTheDocument();
    expect(screen.queryByTestId("query-code-editor")).not.toBeInTheDocument();
    expect(screen.queryByText(EMPTY_STATE)).not.toBeInTheDocument();
  });

  it("renders only the metadata editor when just metadata is present", () => {
    render(
      <ResourceMetadataPanel
        metadata={{ VulnerabilityID: "CVE-2026-0001" }}
        details={null}
      />,
    );

    const editor = screen.getByTestId("query-code-editor");
    expect(editor).toBeInTheDocument();
    // value and copyValue must reference the same serialized string.
    const serialized = JSON.stringify(
      { VulnerabilityID: "CVE-2026-0001" },
      null,
      2,
    );
    expect(editor).toHaveAttribute("data-value", serialized);
    expect(editor).toHaveAttribute("data-copy-value", serialized);
    expect(screen.queryByText("Details:")).not.toBeInTheDocument();
    expect(screen.queryByText(EMPTY_STATE)).not.toBeInTheDocument();
  });

  it("renders both the details card and the metadata editor", () => {
    render(
      <ResourceMetadataPanel
        metadata='{"PkgName":"requests"}'
        details="Detected on instance i-123"
      />,
    );

    expect(screen.getByText("Detected on instance i-123")).toBeInTheDocument();
    expect(screen.getByTestId("query-code-editor")).toBeInTheDocument();
    expect(screen.queryByText(EMPTY_STATE)).not.toBeInTheDocument();
  });

  it("renders the empty state when neither details nor metadata are present", () => {
    render(<ResourceMetadataPanel metadata={null} details={null} />);

    expect(screen.getByText(EMPTY_STATE)).toBeInTheDocument();
    expect(screen.queryByText("Details:")).not.toBeInTheDocument();
    expect(screen.queryByTestId("query-code-editor")).not.toBeInTheDocument();
  });

  it("falls back to the empty state for an empty metadata object", () => {
    render(<ResourceMetadataPanel metadata={{}} details="   " />);

    expect(screen.getByText(EMPTY_STATE)).toBeInTheDocument();
  });
});
