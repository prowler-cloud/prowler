import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ProviderIcon } from "./provider-icon";

vi.mock("@iconify/react", () => ({
  Icon: ({ icon, className }: { icon: string; className?: string }) => (
    <span
      aria-hidden="true"
      className={className}
      data-icon={icon}
      data-testid="provider-logo"
    />
  ),
}));

describe("ProviderIcon", () => {
  it("renders the provider logo for every Lighthouse v2 provider", () => {
    const { rerender } = render(<ProviderIcon provider="openai" />);

    expect(screen.getByTestId("provider-logo")).toHaveAttribute(
      "data-icon",
      "simple-icons:openai",
    );

    rerender(<ProviderIcon provider="bedrock" />);

    expect(screen.getByTestId("provider-logo")).toHaveAttribute(
      "data-icon",
      "simple-icons:amazonwebservices",
    );

    rerender(<ProviderIcon provider="openai-compatible" />);

    expect(screen.getByTestId("provider-logo")).toHaveAttribute(
      "data-icon",
      "simple-icons:openai",
    );
  });
});
