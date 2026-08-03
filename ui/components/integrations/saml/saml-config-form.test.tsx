import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderToString } from "react-dom/server";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import {
  RUNTIME_CONFIG_SCRIPT_ID,
  type RuntimePublicConfig,
} from "@/lib/runtime-config.shared";

import { SamlConfigForm } from "./saml-config-form";

vi.mock("@/actions/integrations", () => ({
  createSamlConfig: vi.fn(),
  updateSamlConfig: vi.fn(),
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({ toast: vi.fn() }),
}));

const runtimeConfig: RuntimePublicConfig = {
  sentryDsn: null,
  sentryEnvironment: null,
  googleTagManagerId: null,
  apiBaseUrl: "https://api.example.com/api/v1",
  apiDocsUrl: null,
  posthogEnabled: false,
  posthogKey: null,
  posthogHost: null,
  reoDevClientId: null,
  cloudEnabled: false,
  cloudBillingEnabled: false,
  stripePublishableKey: null,
  stripePublishableKeyV2: null,
};

beforeAll(() => {
  const runtimeConfigScript = document.createElement("script");
  runtimeConfigScript.id = RUNTIME_CONFIG_SCRIPT_ID;
  runtimeConfigScript.type = "application/json";
  runtimeConfigScript.textContent = JSON.stringify(runtimeConfig);
  document.head.append(runtimeConfigScript);
});

afterAll(() => {
  document.getElementById(RUNTIME_CONFIG_SCRIPT_ID)?.remove();
});

describe("SamlConfigForm", () => {
  it("keeps the ACS field container while generating the URL", async () => {
    // Given
    const serverHtml = renderToString(<SamlConfigForm setIsOpen={vi.fn()} />);
    const user = userEvent.setup();
    const container = document.body.appendChild(document.createElement("div"));
    container.innerHTML = serverHtml;
    render(<SamlConfigForm setIsOpen={vi.fn()} />, {
      container,
      hydrate: true,
    });

    const acsGuidance = screen.getByText(
      "Enter your email domain above to generate the ACS URL.",
    );
    const acsField = acsGuidance.parentElement;

    expect(acsField).toHaveClass("h-10", "w-full");
    expect(
      screen.queryByRole("button", { name: "Copy ACS URL" }),
    ).not.toBeInTheDocument();

    // When
    await user.type(screen.getByLabelText("Email Domain*"), "example.com");

    // Then
    const acsUrl = screen.getByText(
      "https://api.example.com/api/v1/accounts/saml/example.com/acs/",
    );

    expect(acsUrl.parentElement).toBe(acsField);
    expect(screen.getByRole("button", { name: "Copy ACS URL" })).toBeVisible();
  });
});
