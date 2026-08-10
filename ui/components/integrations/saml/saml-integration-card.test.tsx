import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SamlIntegrationCard } from "./saml-integration-card";

vi.mock("@/actions/integrations", () => ({
  deleteSamlConfig: vi.fn(),
}));

vi.mock("./saml-config-form", () => ({
  SamlConfigForm: () => <div>SAML form</div>,
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({ toast: vi.fn() }),
}));

describe("SamlIntegrationCard", () => {
  it("shows the disabled status as a header badge without a status label", () => {
    // When
    render(<SamlIntegrationCard />);

    // Then
    const title = screen.getByRole("heading", {
      name: "SAML SSO Integration",
    });
    const header = title.closest('[data-slot="card-header"]');

    expect(header).toBeInTheDocument();
    expect(header).not.toHaveTextContent("Status:");
    expect(within(header as HTMLElement).getByText("Disabled")).toHaveAttribute(
      "data-slot",
      "badge",
    );
  });

  it("shows the enabled status as a success header badge", () => {
    // When
    render(<SamlIntegrationCard samlConfig={{ id: "saml-1" }} />);

    // Then
    const title = screen.getByRole("heading", {
      name: "SAML SSO Integration",
    });
    const header = title.closest('[data-slot="card-header"]');
    const badge = within(header as HTMLElement).getByText("Enabled");

    expect(header).not.toHaveTextContent("Status:");
    expect(badge).toHaveAttribute("data-slot", "badge");
    expect(badge).toHaveClass("bg-bg-pass-secondary");
  });
});
