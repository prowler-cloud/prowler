import { fireEvent, render, screen } from "@testing-library/react";
import type { ComponentProps, ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { createSamlConfigMock, updateSamlConfigMock, toastMock } = vi.hoisted(
  () => ({
    createSamlConfigMock: vi.fn(),
    updateSamlConfigMock: vi.fn(),
    toastMock: vi.fn(),
  }),
);

vi.mock("@/actions/integrations", () => ({
  createSamlConfig: createSamlConfigMock,
  updateSamlConfig: updateSamlConfigMock,
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: toastMock }),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test.prowler.com/api/v1",
}));

vi.mock("@/components/ui/code-snippet/code-snippet", () => ({
  CodeSnippet: ({
    value,
    ariaLabel,
  }: {
    value: string;
    ariaLabel?: string;
  }) => (
    <div data-testid="code-snippet" data-aria-label={ariaLabel}>
      {value}
    </div>
  ),
}));

vi.mock("@/components/ui/custom", () => ({
  CustomServerInput: ({
    name,
    label,
    value,
    onChange,
  }: {
    name: string;
    label: string;
    value: string;
    onChange: (event: React.ChangeEvent<HTMLInputElement>) => void;
  }) => (
    <label>
      {label}
      <input name={name} value={value} onChange={onChange} />
    </label>
  ),
}));

vi.mock("@/components/ui/custom/custom-link", () => ({
  CustomLink: ({ children, href }: { children: ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock("@/components/ui/form", () => ({
  FormButtons: () => <div data-testid="form-buttons" />,
}));

vi.mock("@/components/shadcn", () => ({
  Button: ({ children, ...rest }: ComponentProps<"button">) => (
    <button {...rest}>{children}</button>
  ),
  Card: ({ children }: { children: ReactNode }) => (
    <section>{children}</section>
  ),
  CardContent: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  CardHeader: ({ children }: { children: ReactNode }) => (
    <header>{children}</header>
  ),
}));

vi.mock("@/components/icons", () => ({
  AddIcon: () => <span data-testid="add-icon" />,
}));

import { SamlConfigForm } from "./saml-config-form";

const findAcsSnippet = () =>
  screen
    .queryAllByTestId("code-snippet")
    .find((node) => node.getAttribute("data-aria-label") === "Copy ACS URL");

describe("SamlConfigForm — ACS URL visibility", () => {
  beforeEach(() => {
    createSamlConfigMock.mockReset();
    updateSamlConfigMock.mockReset();
    toastMock.mockReset();
  });

  it("does not render the ACS URL snippet when the email domain is empty", () => {
    render(<SamlConfigForm setIsOpen={vi.fn()} />);

    expect(findAcsSnippet()).toBeUndefined();
    // The legacy `your-domain.com` placeholder must never reach the DOM —
    // copying it caused SAML dispatch errors in the API.
    expect(screen.queryByText(/your-domain\.com/)).toBeNull();
    expect(
      screen.getByText(/Enter your email domain above to generate the ACS URL/),
    ).toBeInTheDocument();
  });

  it("renders the ACS URL with the typed domain once the email domain is filled", () => {
    render(<SamlConfigForm setIsOpen={vi.fn()} />);

    fireEvent.change(screen.getByLabelText("Email Domain"), {
      target: { value: "acme.com" },
    });

    const snippet = findAcsSnippet();
    expect(snippet).toBeDefined();
    expect(snippet).toHaveTextContent(
      "https://api.test.prowler.com/api/v1/accounts/saml/acme.com/acs/",
    );
    expect(screen.queryByText(/your-domain\.com/)).toBeNull();
  });

  it("treats whitespace-only domains as empty and hides the ACS URL", () => {
    render(<SamlConfigForm setIsOpen={vi.fn()} />);

    fireEvent.change(screen.getByLabelText("Email Domain"), {
      target: { value: "   " },
    });

    expect(findAcsSnippet()).toBeUndefined();
    expect(screen.queryByText(/your-domain\.com/)).toBeNull();
  });

  it("pre-fills the ACS URL when editing an existing SAML config", () => {
    render(
      <SamlConfigForm
        setIsOpen={vi.fn()}
        samlConfig={{
          id: "saml-1",
          attributes: { email_domain: "existing.com" },
        }}
      />,
    );

    const snippet = findAcsSnippet();
    expect(snippet).toBeDefined();
    expect(snippet).toHaveTextContent(
      "https://api.test.prowler.com/api/v1/accounts/saml/existing.com/acs/",
    );
  });
});
