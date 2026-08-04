import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderToString } from "react-dom/server";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import {
  RUNTIME_CONFIG_SCRIPT_ID,
  type RuntimePublicConfig,
} from "@/lib/runtime-config.shared";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import { SAML_CONFIGURATION_RESOURCE_TYPE } from "@/types/saml";

import { SamlConfigForm } from "./saml-config-form";

vi.mock("@/actions/integrations", () => ({
  createSamlConfig: vi.fn(),
  updateSamlConfig: vi.fn(),
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({ toast: vi.fn() }),
}));

const { isCloudMock } = vi.hoisted(() => ({ isCloudMock: vi.fn() }));

vi.mock("@/lib/shared/env", () => ({
  isCloud: isCloudMock,
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

beforeEach(() => {
  isCloudMock.mockReturnValue(false);
  useCloudUpgradeStore.getState().closeCloudUpgrade();
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
    await user.type(
      screen.getByLabelText("Primary Email Domain*"),
      "example.com",
    );

    // Then
    const acsUrl = screen.getByText(
      "https://api.example.com/api/v1/accounts/saml/example.com/acs/",
    );

    expect(acsUrl.parentElement).toBe(acsField);
    expect(screen.getByRole("button", { name: "Copy ACS URL" })).toBeVisible();
  });

  it("keeps single-domain SAML available in OSS and opens the Cloud upgrade for aliases", async () => {
    // Given
    const user = userEvent.setup();
    render(<SamlConfigForm setIsOpen={vi.fn()} />);

    // When
    const cloudUpgradeButton = screen.getByRole("button", {
      name: "Additional email domains are available in Prowler Cloud",
    });

    await user.click(cloudUpgradeButton);

    // Then
    expect(screen.getByLabelText("Primary Email Domain*")).toBeEnabled();
    expect(
      screen.queryByLabelText("Additional Email Domain"),
    ).not.toBeInTheDocument();
    expect(cloudUpgradeButton).toHaveClass("border-0", "bg-transparent", "p-0");
    expect(
      screen.getByText("Additional Email Domains").parentElement,
    ).toContainElement(cloudUpgradeButton);
    expect(screen.getByText("Available in Prowler Cloud")).toBeVisible();
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.SAML_DOMAINS,
    );
  });

  it("loads existing aliases in Cloud and keeps the canonical ACS", () => {
    // Given
    isCloudMock.mockReturnValue(true);
    const samlConfig = {
      type: SAML_CONFIGURATION_RESOURCE_TYPE,
      id: "saml-1",
      attributes: {
        email_domain: "primary.example.com",
        additional_email_domains: [
          "subsidiary.example.com",
          "division.example.com",
        ],
        metadata_xml: "<EntityDescriptor />",
      },
    };

    // When
    render(<SamlConfigForm setIsOpen={vi.fn()} samlConfig={samlConfig} />);

    // Then
    expect(screen.getByText("subsidiary.example.com")).toBeVisible();
    expect(screen.getByText("division.example.com")).toBeVisible();
    expect(
      screen.getByText(
        "https://api.example.com/api/v1/accounts/saml/primary.example.com/acs/",
      ),
    ).toBeVisible();
    expect(
      screen.queryByText(/accounts\/saml\/subsidiary\.example\.com\/acs/),
    ).not.toBeInTheDocument();
  });

  it("does not mark metadata XML as required when updating", () => {
    // Given
    isCloudMock.mockReturnValue(true);
    const samlConfig = {
      type: SAML_CONFIGURATION_RESOURCE_TYPE,
      id: "saml-1",
      attributes: {
        email_domain: "primary.example.com",
        metadata_xml: "<EntityDescriptor />",
      },
    };

    // When
    render(<SamlConfigForm setIsOpen={vi.fn()} samlConfig={samlConfig} />);

    // Then
    expect(screen.getByText("Metadata XML File")).not.toHaveTextContent("*");
  });

  it("does not require metadata when an update file selection is cleared", async () => {
    // Given
    isCloudMock.mockReturnValue(true);
    const user = userEvent.setup();
    const samlConfig = {
      type: SAML_CONFIGURATION_RESOURCE_TYPE,
      id: "saml-1",
      attributes: {
        email_domain: "primary.example.com",
        metadata_xml: "<EntityDescriptor />",
      },
    };
    render(<SamlConfigForm setIsOpen={vi.fn()} samlConfig={samlConfig} />);
    const fileInput = document.getElementById(
      "metadata_xml_file",
    ) as HTMLInputElement;
    const metadataFile = new File(["<EntityDescriptor />"], "metadata.xml", {
      type: "application/xml",
    });
    await user.upload(fileInput, metadataFile);

    // When
    await user.upload(fileInput, []);

    // Then
    expect(
      screen.queryByText("Metadata XML is required"),
    ).not.toBeInTheDocument();
  });

  it("marks metadata XML as required when creating", () => {
    // Given
    isCloudMock.mockReturnValue(true);

    // When
    render(<SamlConfigForm setIsOpen={vi.fn()} />);

    // Then
    expect(screen.getByText("Metadata XML File")).toHaveTextContent("*");
  });

  it("adds normalized aliases and removes them in Cloud", async () => {
    // Given
    isCloudMock.mockReturnValue(true);
    const user = userEvent.setup();
    render(<SamlConfigForm setIsOpen={vi.fn()} />);

    // When
    await user.type(
      screen.getByLabelText("Additional Email Domain"),
      " Subsidiary.Example.com ",
    );
    await user.click(screen.getByRole("button", { name: "Add domain" }));

    // Then
    expect(screen.getByText("subsidiary.example.com")).toBeVisible();
    expect(
      document.querySelectorAll(
        'input[name="additional_email_domains"][value="subsidiary.example.com"]',
      ),
    ).toHaveLength(1);

    // When
    await user.click(
      screen.getByRole("button", {
        name: "Remove subsidiary.example.com",
      }),
    );

    // Then
    expect(
      screen.queryByText("subsidiary.example.com"),
    ).not.toBeInTheDocument();
    expect(
      document.querySelectorAll('input[name="additional_email_domains"]'),
    ).toHaveLength(0);
  });

  it("shows a contextual error when an additional domain is required", async () => {
    // Given
    isCloudMock.mockReturnValue(true);
    const user = userEvent.setup();
    render(<SamlConfigForm setIsOpen={vi.fn()} />);

    // When
    await user.click(screen.getByRole("button", { name: "Add domain" }));

    // Then
    expect(
      screen.getByText("Additional email domain is required"),
    ).toBeVisible();
  });

  it("keeps the maximum alias set inside a compact scroll region", () => {
    // Given
    isCloudMock.mockReturnValue(true);
    const additionalEmailDomains = Array.from(
      { length: 19 },
      (_, index) => `alias-${index + 1}.example.com`,
    );
    const samlConfig = {
      type: SAML_CONFIGURATION_RESOURCE_TYPE,
      id: "saml-1",
      attributes: {
        email_domain: "primary.example.com",
        additional_email_domains: additionalEmailDomains,
        metadata_xml: "<EntityDescriptor />",
      },
    };

    // When
    render(<SamlConfigForm setIsOpen={vi.fn()} samlConfig={samlConfig} />);

    // Then
    expect(screen.getByText("19 / 19 domains")).toBeVisible();
    expect(
      screen.getByRole("list", { name: "Additional email domains" }),
    ).toHaveClass("max-h-24", "overflow-y-auto");
    expect(screen.getByLabelText("Additional Email Domain")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Add domain" })).toBeDisabled();
    expect(
      screen.getAllByRole("button", { name: /^Remove alias-/ }),
    ).toHaveLength(19);
  });

  it("rejects a duplicate alias before submission", async () => {
    // Given
    isCloudMock.mockReturnValue(true);
    const user = userEvent.setup();
    const samlConfig = {
      type: SAML_CONFIGURATION_RESOURCE_TYPE,
      id: "saml-1",
      attributes: {
        email_domain: "primary.example.com",
        additional_email_domains: ["alias.example.com"],
        metadata_xml: "<EntityDescriptor />",
      },
    };
    render(<SamlConfigForm setIsOpen={vi.fn()} samlConfig={samlConfig} />);

    // When
    await user.type(
      screen.getByLabelText("Additional Email Domain"),
      " ALIAS.EXAMPLE.COM ",
    );
    await user.click(screen.getByRole("button", { name: "Add domain" }));

    // Then
    expect(
      screen.getByText("This domain has already been added."),
    ).toBeVisible();
    expect(screen.getAllByText("alias.example.com")).toHaveLength(1);
  });
});
