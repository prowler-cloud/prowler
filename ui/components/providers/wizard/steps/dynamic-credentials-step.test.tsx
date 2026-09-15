import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import openaiSchema from "@/lib/provider-credentials/fixtures/openai-credential-schema.json";
import templateSchema from "@/lib/provider-credentials/fixtures/template-credential-schema.json";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import type { ProviderSchemasResult } from "@/types/provider-schema";

const { getProviderSchemas, saveDynamicProviderCredentials, toast } =
  vi.hoisted(() => ({
    getProviderSchemas: vi.fn(),
    saveDynamicProviderCredentials: vi.fn(),
    toast: vi.fn(),
  }));
vi.mock("@/actions/providers/provider-schemas", () => ({ getProviderSchemas }));
vi.mock("@/actions/providers/dynamic-provider-credentials", () => ({
  saveDynamicProviderCredentials,
}));
vi.mock("@/components/shadcn/toast", () => ({ useToast: () => ({ toast }) }));

import { DynamicCredentialsStep } from "./dynamic-credentials-step";

beforeAll(() => {
  for (const method of [
    "hasPointerCapture",
    "setPointerCapture",
    "releasePointerCapture",
    "scrollIntoView",
  ]) {
    Object.defineProperty(HTMLElement.prototype, method, {
      configurable: true,
      value: vi.fn(() => false),
    });
  }
});

const props = {
  providerId: "account",
  providerType: "acme",
  onNext: vi.fn(),
  onBack: vi.fn(),
  onFooterChange: vi.fn(),
};
const schema = {
  type: "object",
  description: openaiSchema.description,
  properties: {
    token: {
      type: "string",
      title: "API token",
      format: "password",
      writeOnly: true,
    },
  },
  required: ["token"],
};

describe("dynamic credentials in the provider wizard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    localStorage.clear();
    useProviderWizardStore.getState().reset();
    getProviderSchemas.mockResolvedValue({
      status: "success",
      providerType: "acme",
      secretTypes: { api_key: schema },
    });
    saveDynamicProviderCredentials.mockResolvedValue({
      status: "saved",
      secretId: "secret",
    });
  });
  it("saves through the dynamic action and never persists entered secrets", async () => {
    render(<DynamicCredentialsStep {...props} />);
    const field = await screen.findByLabelText(/API token/);
    fireEvent.change(field, { target: { value: "only-in-memory" } });
    expect(JSON.stringify(sessionStorage)).not.toContain("only-in-memory");
    expect(JSON.stringify(localStorage)).not.toContain("only-in-memory");
    fireEvent.submit(field.closest("form")!);
    await waitFor(() => expect(props.onNext).toHaveBeenCalledOnce());
    expect(saveDynamicProviderCredentials).toHaveBeenCalledWith({
      providerId: "account",
      secretType: "api_key",
      secret: { token: "only-in-memory" },
    });
    expect(useProviderWizardStore.getState().secretId).toBe("secret");
    expect(field).toHaveValue("");
  });
  it("masks the OpenAI API key and submits the original credential values", async () => {
    // Given
    const user = userEvent.setup();
    getProviderSchemas.mockResolvedValue({
      status: "success",
      providerType: "openai",
      secretTypes: { api_key: openaiSchema },
    });
    render(<DynamicCredentialsStep {...props} providerType="openai" />);
    const apiKey = await screen.findByLabelText(/Platform Api Key/);
    const organization = screen.getByLabelText(/Organization Id/);
    const baseUrl = screen.getByLabelText(/Base Url/);

    // When
    await user.type(organization, "org-fixture");
    await user.type(apiKey, "fixture-key-not-a-secret");

    // Then
    expect(apiKey).toHaveAttribute("type", "password");
    expect(apiKey).toHaveAttribute("autocomplete", "new-password");
    expect(organization).toHaveAttribute("type", "text");
    expect(baseUrl).toHaveAttribute("type", "text");
    expect(
      screen.queryByRole("button", { name: /show|reveal/i }),
    ).not.toBeInTheDocument();

    // When / Then: this form submits from the wizard's external footer.
    act(() => apiKey.closest("form")!.requestSubmit());
    await waitFor(() => expect(props.onNext).toHaveBeenCalledOnce());
    expect(saveDynamicProviderCredentials).toHaveBeenCalledWith({
      providerId: "account",
      secretType: "api_key",
      secret: {
        organization_id: "org-fixture",
        platform_api_key: "fixture-key-not-a-secret",
        base_url: "https://api.openai.com/v1",
      },
    });
  });
  it("renders and submits the installed Template credential form with typed values", async () => {
    // Given
    const user = userEvent.setup();
    getProviderSchemas.mockResolvedValue({
      status: "success",
      providerType: "template",
      secretTypes: { static: templateSchema },
    });
    render(<DynamicCredentialsStep {...props} providerType="template" />);
    const apiUrl = await screen.findByLabelText(/API URL/);
    const apiKey = screen.getByLabelText(/API Key/);
    const verifyTls = screen.getByRole("checkbox", { name: "Verify TLS" });
    const timeout = screen.getByRole("spinbutton", { name: "Timeout" });

    // Then
    expect(apiUrl).toHaveAttribute("placeholder", "https://api.acme.com");
    expect(apiKey).toHaveAttribute("type", "password");
    expect(screen.getByLabelText("CA Bundle").tagName).toBe("TEXTAREA");
    expect(verifyTls).toBeChecked();
    expect(timeout).toHaveValue(30);
    expect(timeout).toHaveAttribute("min", "1");
    expect(timeout).toHaveAttribute("max", "300");
    expect(timeout).toHaveAttribute("step", "1");
    expect(
      screen.getByRole("combobox", { name: "Authentication Scheme" }),
    ).toHaveTextContent("bearer");
    expect(apiUrl).toHaveValue("");

    // When: false must remain a boolean and numeric input must become a number.
    await user.type(apiUrl, "https://api.example.test");
    await user.type(apiKey, "fixture-key-not-a-secret");
    await user.click(verifyTls);
    await user.clear(timeout);
    await user.type(timeout, "60");
    act(() => apiKey.closest("form")!.requestSubmit());

    // Then
    await waitFor(() => expect(props.onNext).toHaveBeenCalledOnce());
    expect(saveDynamicProviderCredentials).toHaveBeenCalledWith({
      providerId: "account",
      secretType: "static",
      secret: {
        api_url: "https://api.example.test",
        api_key: "fixture-key-not-a-secret",
        verify_tls: false,
        timeout_seconds: 60,
        auth_scheme: "bearer",
      },
    });
  });
  it.each<{ result: ProviderSchemasResult; title: string }>([
    {
      result: { status: "success", providerType: "acme", secretTypes: {} },
      title: "Credential form unavailable",
    },
    {
      result: {
        status: "success",
        providerType: "acme",
        secretTypes: {
          api_key: {
            type: "object",
            properties: { nested: { type: "object" } },
          },
        },
      },
      title: "Credential form not supported",
    },
    {
      result: { status: "access_denied" },
      title: "Access required",
    },
    {
      result: { status: "unavailable" },
      title: "Provider installation unavailable",
    },
  ])(
    "explains $title without allowing credential submission",
    async ({ result, title }) => {
      getProviderSchemas.mockResolvedValue(result);
      render(<DynamicCredentialsStep {...props} />);
      expect(
        await screen.findByRole("button", { name: "Try again" }),
      ).toBeVisible();
      expect(screen.getByRole("alert")).toHaveTextContent(title);
      expect(screen.queryByLabelText(/API token/)).not.toBeInTheDocument();
      expect(saveDynamicProviderCredentials).not.toHaveBeenCalled();
    },
  );
  it("explains a loading failure and recovers when retried", async () => {
    // Given
    getProviderSchemas.mockRejectedValueOnce(new Error("Network unavailable"));
    const user = userEvent.setup();
    render(<DynamicCredentialsStep {...props} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not load credential form",
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Check your connection and try again.",
    );
    expect(screen.getByRole("link", { name: "Open Registry" })).toHaveAttribute(
      "href",
      "/registry",
    );

    // When
    await user.click(screen.getByRole("button", { name: "Try again" }));

    // Then
    expect(await screen.findByLabelText(/API token/)).toBeVisible();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
  it("clears credentials when changing providers", async () => {
    const view = render(<DynamicCredentialsStep {...props} />);
    fireEvent.change(await screen.findByLabelText(/API token/), {
      target: { value: "previous-secret" },
    });
    view.rerender(
      <DynamicCredentialsStep
        {...props}
        providerId="other"
        providerType="other"
      />,
    );
    await waitFor(() =>
      expect(screen.getByLabelText(/API token/)).toHaveValue(""),
    );
  });
  it("clears credentials when switching authentication methods", async () => {
    getProviderSchemas.mockResolvedValue({
      status: "success",
      providerType: "acme",
      secretTypes: { api_key: schema, personal_token: schema },
    });
    render(<DynamicCredentialsStep {...props} />);
    fireEvent.change(await screen.findByLabelText(/API token/), {
      target: { value: "previous-method-secret" },
    });
    const user = userEvent.setup();
    await user.click(
      screen.getByRole("combobox", { name: "Authentication method" }),
    );
    await user.click(screen.getByRole("option", { name: "personal token" }));
    expect(screen.getByLabelText(/API token/)).toHaveValue("");
    expect(JSON.stringify(sessionStorage)).not.toContain(
      "previous-method-secret",
    );
    expect(JSON.stringify(localStorage)).not.toContain(
      "previous-method-secret",
    );
  });
  it("rejects double submission and retries a failed save for the same account", async () => {
    let rejectSave!: (error: Error) => void;
    saveDynamicProviderCredentials.mockImplementationOnce(
      () =>
        new Promise((_resolve, reject) => {
          rejectSave = reject;
        }),
    );
    render(<DynamicCredentialsStep {...props} />);
    const field = await screen.findByLabelText(/API token/);
    fireEvent.change(field, { target: { value: "retry-secret" } });
    fireEvent.submit(field.closest("form")!);
    fireEvent.submit(field.closest("form")!);
    expect(saveDynamicProviderCredentials).toHaveBeenCalledOnce();
    rejectSave(new Error("Network unavailable"));
    await screen.findByText(
      "Could not save the credentials. Check your connection and retry.",
    );
    expect(props.onNext).not.toHaveBeenCalled();
    fireEvent.submit(field.closest("form")!);
    await waitFor(() => expect(props.onNext).toHaveBeenCalledOnce());
    expect(saveDynamicProviderCredentials).toHaveBeenCalledTimes(2);
    expect(saveDynamicProviderCredentials).toHaveBeenLastCalledWith({
      providerId: "account",
      secretType: "api_key",
      secret: { token: "retry-secret" },
    });
  });
  it("keeps other field and form errors visible while editing one credential", async () => {
    // Given
    const user = userEvent.setup();
    getProviderSchemas.mockResolvedValue({
      status: "success",
      providerType: "acme",
      secretTypes: {
        api_key: {
          ...schema,
          properties: {
            ...schema.properties,
            project: { type: "string", title: "Project" },
          },
          required: ["token", "project"],
        },
      },
    });
    saveDynamicProviderCredentials.mockResolvedValueOnce({
      status: "invalid",
      errors: {
        token: "Token was rejected",
        project: "Project is unavailable",
        _form: "Review the credential fields",
      },
    });
    render(<DynamicCredentialsStep {...props} />);
    const token = await screen.findByLabelText(/API token/);
    await user.type(token, "fixture-token");
    await user.type(screen.getByLabelText(/Project/), "fixture-project");
    act(() => token.closest("form")!.requestSubmit());
    expect(await screen.findByText("Token was rejected")).toBeVisible();

    // When
    await user.type(token, "-edited");

    // Then
    expect(screen.queryByText("Token was rejected")).not.toBeInTheDocument();
    expect(screen.getByText("Project is unavailable")).toBeVisible();
    expect(screen.getByText("Review the credential fields")).toBeVisible();

    // When / Then: submitting again replaces the earlier validation errors.
    act(() => token.closest("form")!.requestSubmit());
    await waitFor(() => expect(props.onNext).toHaveBeenCalledOnce());
    expect(
      screen.queryByText("Project is unavailable"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("Review the credential fields"),
    ).not.toBeInTheDocument();
  });
});
