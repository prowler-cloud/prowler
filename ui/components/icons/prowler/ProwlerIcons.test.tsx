import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProwlerBrand, ProwlerShort } from "./ProwlerIcons";

describe("ProwlerBrand (Cloudy mark)", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
  });

  it.each(["false", "true"])(
    "renders the Cloudy mark and wordmark whatever UI_CLOUD_ENABLED is (%s)",
    (cloudEnabled) => {
      vi.stubEnv("UI_CLOUD_ENABLED", cloudEnabled);

      render(<ProwlerBrand />);

      const logo = screen.getByRole("img", { name: "Cloudy" });
      expect(logo.querySelector("svg")).not.toBeNull();
      expect(logo.querySelector("img")).toBeNull();
      expect(logo).toHaveTextContent("Cloudy");
    },
  );

  it("draws the short mark as an accessible image", () => {
    render(<ProwlerShort />);

    expect(screen.getByRole("img", { name: "Cloudy" })).toBeInTheDocument();
  });
});
