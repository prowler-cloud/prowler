import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ChecksWithProviders } from "./checks-with-providers";

// The real icon lazy-loads SVG chunks behind Suspense; irrelevant here.
vi.mock("@/components/icons/providers-badge/provider-type-icon", () => ({
  ProviderTypeIcon: ({ type }: { type: string }) => (
    <span data-testid={`provider-icon-${type}`} />
  ),
}));

describe("ChecksWithProviders", () => {
  it("renders every check id with the icons of its providers", () => {
    render(
      <ChecksWithProviders
        checks={["aws_check", "shared_check"]}
        checkProviders={{
          aws_check: ["aws"],
          shared_check: ["aws", "azure"],
        }}
      />,
    );

    const awsCheck = screen.getByTestId("check-with-providers-aws_check");
    expect(awsCheck).toHaveTextContent("aws_check");
    expect(
      within(awsCheck).getByTestId("provider-icon-aws"),
    ).toBeInTheDocument();

    const sharedCheck = screen.getByTestId("check-with-providers-shared_check");
    expect(sharedCheck).toHaveTextContent("shared_check");
    expect(
      within(sharedCheck).getByTestId("provider-icon-aws"),
    ).toBeInTheDocument();
    expect(
      within(sharedCheck).getByTestId("provider-icon-azure"),
    ).toBeInTheDocument();
  });

  it("renders a check without icons when the map has no entry for it", () => {
    render(
      <ChecksWithProviders checks={["orphan_check"]} checkProviders={{}} />,
    );

    const orphan = screen.getByTestId("check-with-providers-orphan_check");
    expect(orphan).toHaveTextContent("orphan_check");
    expect(within(orphan).queryAllByTestId(/provider-icon/)).toHaveLength(0);
  });
});
