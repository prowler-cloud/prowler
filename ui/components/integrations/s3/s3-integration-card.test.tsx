import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { S3IntegrationCard } from "./s3-integration-card";

describe("S3IntegrationCard", () => {
  it("marks Amazon S3 as a Cloud feature on Local Server, still manageable", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    render(<S3IntegrationCard />);

    // Then
    expect(screen.getByText("Cloud")).toBeVisible();
    expect(screen.getByRole("link", { name: /Manage/ })).toHaveAttribute(
      "href",
      "/integrations/amazon-s3",
    );
  });

  it("shows no Cloud badge in Prowler Cloud", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

    // When
    render(<S3IntegrationCard />);

    // Then
    expect(screen.queryByText("Cloud")).not.toBeInTheDocument();
  });
});
