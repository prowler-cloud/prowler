import { render, screen } from "@testing-library/react";
import { FormProvider, useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import { AzureCertificateCredentials } from "@/types";

import { AzureCertificateCredentialsForm } from "./azure-certificate-credentials-form";

const Harness = () => {
  const form = useForm<AzureCertificateCredentials>();
  return (
    <FormProvider {...form}>
      <AzureCertificateCredentialsForm control={form.control} />
    </FormProvider>
  );
};

const expectExternalLinkIcon = (link: HTMLElement) => {
  const icon = link.querySelector("svg.lucide-external-link");

  expect(icon).toBeInTheDocument();
  expect(icon).toHaveAttribute("aria-hidden", "true");
  expect(icon).toHaveClass("size-3.5", "shrink-0");
};

describe("AzureCertificateCredentialsForm", () => {
  it("renders the Deploy to Azure link with the docs-hosted template", () => {
    // Given
    render(<Harness />);

    // When
    const link = screen.getByRole("link", { name: "Deploy to Azure" });

    // Then
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveAttribute(
      "href",
      "https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fdocs.prowler.com%2Fassets%2Ftemplates%2Fazure%2Fprowler-scan.json",
    );
  });

  it("links the manual template fallback to the docs-hosted JSON", () => {
    // Given / When
    render(<Harness />);

    // Then
    const link = screen.getByRole("link", { name: "Open template" });
    expect(link).toHaveAttribute(
      "href",
      "https://docs.prowler.com/assets/templates/azure/prowler-scan.json",
    );
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expectExternalLinkIcon(link);
    expect(
      screen.getByText(/build your own template in the editor/i),
    ).toBeInTheDocument();
  });

  it("renders every external link with the shared icon and safe attributes", () => {
    // Given
    render(<Harness />);

    // When / Then
    const links = [
      {
        element: screen.getByRole("link", { name: "Full guide" }),
        href: "https://docs.prowler.com/user-guide/providers/azure/authentication#certificate-authentication",
      },
      {
        element: screen.getByRole("link", { name: "Open Azure" }),
        href: "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/CreateApplicationBlade",
      },
      {
        element: screen.getByRole("link", {
          name: "Enterprise applications",
        }),
        href: "https://portal.azure.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview",
      },
      {
        element: screen.getByRole("link", { name: "Deploy to Azure" }),
      },
      {
        element: screen.getByRole("link", { name: "Open template" }),
        href: "https://docs.prowler.com/assets/templates/azure/prowler-scan.json",
      },
    ];

    for (const { element, href } of links) {
      if (href) expect(element).toHaveAttribute("href", href);
      expect(element).toHaveAttribute("target", "_blank");
      expect(element).toHaveAttribute("rel", "noopener noreferrer");
      expectExternalLinkIcon(element);
    }
  });

  it("renders the approved six-step certificate onboarding guidance", () => {
    // Given / When
    render(<Harness />);

    // Then
    const steps = screen.getAllByRole("listitem");
    expect(steps).toHaveLength(6);
    expect(steps[0]).toHaveTextContent(
      "Register an Azure application. From its Overview page, copy the Directory (tenant) ID and Application (client) ID.",
    );
    expect(steps[1]).toHaveTextContent(
      "Generate a certificate. The private bundle fills the field below and prowler-cert.cer downloads for step 3.",
    );
    expect(steps[2]).toHaveTextContent(
      "In your App Registration, upload prowler-cert.cer under Certificates & secrets. Then in API permissions, add the Microsoft Graph application permissions AuditLog.Read.All, Directory.Read.All, and Policy.Read.All, and click Grant admin consent.",
    );
    expect(steps[3]).toHaveTextContent(
      "Open Enterprise applications, select the same app, and copy its Object ID (different from the App Registration's Object ID).",
    );
    expect(steps[4]).toHaveTextContent(
      "Deploy the template with the Service Principal Object ID from step 4. It grants Reader and a custom ProwlerRole on the subscription.",
    );
    expect(steps[5]).toHaveTextContent(
      "Return to Prowler and paste the Tenant ID and Client ID from step 1 into the fields below. The certificate field is already filled.",
    );
    expect(
      screen.getByRole("textbox", {
        name: "Certificate and Private Key Bundle (Base64)",
      }),
    ).toHaveAttribute(
      "placeholder",
      "Auto-filled by 'Generate certificate', or paste your own",
    );
  });
});
