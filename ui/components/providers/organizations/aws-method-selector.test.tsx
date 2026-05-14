import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AwsMethodSelector } from "./aws-method-selector";

describe("AwsMethodSelector", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("links the OSS AWS Organizations badge to pricing", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    render(
      <AwsMethodSelector
        onSelectSingle={vi.fn()}
        onSelectOrganizations={vi.fn()}
      />,
    );

    // Then
    expect(
      screen.getByRole("link", { name: /available in prowler cloud/i }),
    ).toHaveAttribute("href", "https://prowler.com/pricing");
  });
});
