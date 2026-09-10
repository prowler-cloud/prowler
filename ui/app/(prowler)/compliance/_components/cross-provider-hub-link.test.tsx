import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CrossProviderHubLink } from "./cross-provider-hub-link";

describe("CrossProviderHubLink", () => {
  it("opens the framework page in Prowler Hub safely", () => {
    // Given / When
    render(<CrossProviderHubLink complianceId="cis_controls_8.1" />);

    // Then
    const link = screen.getByRole("link", { name: /view on prowler hub/i });
    expect(link).toHaveAttribute(
      "href",
      "https://hub.prowler.com/compliance/cis_controls_8.1",
    );
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });
});
