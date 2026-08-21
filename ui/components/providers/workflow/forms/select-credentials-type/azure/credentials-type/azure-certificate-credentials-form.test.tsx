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
        element: screen.getByRole("link", { name: "New App Registration" }),
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
      "1. Create an App Registration. Copy its Directory (tenant) ID and Application (client) ID.",
    );
    expect(steps[1]).toHaveTextContent(
      "2. Generate the certificate bundle and upload the public prowler-cert.cer file under Certificates & secrets. The private bundle is filled below and is submitted to Prowler only when you connect.",
    );
    expect(steps[2]).toHaveTextContent(
      "3. Add Microsoft Graph application permissions: AuditLog.Read.All, Directory.Read.All (or Domain.Read.All), and Policy.Read.All. Then grant admin consent.",
    );
    expect(steps[3]).toHaveTextContent(
      "4. Copy the Service Principal Object ID from Enterprise applications.",
    );
    expect(steps[4]).toHaveTextContent(
      "5. Deploy subscription RBAC with that Service Principal Object ID. The template creates ProwlerRole and assigns Reader and ProwlerRole; it does not create Entra resources.",
    );
    expect(steps[5]).toHaveTextContent(
      "6. Return to Prowler and connect. Paste the Tenant ID and Application Client ID below; the generated certificate bundle is already filled.",
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
