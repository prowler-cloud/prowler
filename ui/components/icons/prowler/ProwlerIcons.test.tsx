import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProwlerBrand } from "./ProwlerIcons";

describe("ProwlerBrand", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
  });

  it("should render the Local Server lockups outside Cloud", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    render(<ProwlerBrand />);

    // Then
    const logo = screen.getByRole("img", { name: "Prowler Local Server" });
    const sources = Array.from(logo.querySelectorAll("img"), (image) =>
      image.getAttribute("src"),
    );

    expect(sources).toEqual([
      "/logos/prowler-local-server-light.svg",
      "/logos/prowler-local-server-dark.svg",
    ]);
  });

  it("should render the Prowler Cloud lockups in Cloud", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    render(<ProwlerBrand />);

    // Then
    const logo = screen.getByRole("img", { name: "Prowler Cloud" });
    const sources = Array.from(logo.querySelectorAll("img"), (image) =>
      image.getAttribute("src"),
    );

    expect(sources).toEqual([
      "/logos/prowler-cloud-light.svg",
      "/logos/prowler-cloud-dark.svg",
    ]);
  });
});
