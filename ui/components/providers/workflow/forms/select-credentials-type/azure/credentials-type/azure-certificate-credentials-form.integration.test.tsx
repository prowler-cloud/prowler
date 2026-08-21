import { FormProvider, useForm } from "react-hook-form";
import { describe, expect, vi } from "vitest";

import { it } from "@/__tests__/fixtures";
import { render } from "@/__tests__/render-browser";
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

describe("AzureCertificateCredentialsForm browser flow", () => {
  it("groups the six setup steps into three named phases before the form", async () => {
    // When
    const view = await render(<Harness />);

    // Then
    const phaseHeadings = [
      view.getByRole("heading", { name: "Create the application" }).element(),
      view.getByRole("heading", { name: "Configure access" }).element(),
      view.getByRole("heading", { name: "Deploy and connect" }).element(),
    ];
    const phases = phaseHeadings.map((heading) => heading.closest("section"));

    expect(phases.every((phase) => phase !== null)).toBe(true);
    expect(phases.map((phase) => phase?.querySelectorAll("li").length)).toEqual(
      [2, 2, 2],
    );
    const openAzureLink = view
      .getByRole("link", { name: "Open Azure" })
      .element();
    const enterpriseApplicationsLink = view
      .getByRole("link", { name: "Enterprise applications" })
      .element();
    const deployToAzureLink = view
      .getByRole("link", { name: "Deploy to Azure" })
      .element();
    const openTemplateLink = view
      .getByRole("link", { name: "Open template" })
      .element();

    expect(phases[0]).toContainElement(openAzureLink);
    expect(phases[0]).toContainElement(
      view.getByRole("button", { name: "Generate certificate" }).element(),
    );
    expect(phases[1]).toContainElement(enterpriseApplicationsLink);
    expect(phases[2]).toContainElement(deployToAzureLink);
    expect(deployToAzureLink.closest("li")).toContainElement(openTemplateLink);
    expect(openAzureLink).toHaveAttribute(
      "href",
      "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/CreateApplicationBlade",
    );
    expect(enterpriseApplicationsLink).toHaveAttribute(
      "href",
      "https://portal.azure.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview",
    );
    const guidance = phaseHeadings[0].parentElement?.parentElement;
    const tenantIdInput = view
      .getByRole("textbox", { name: "Tenant ID" })
      .element();
    expect(guidance?.nextElementSibling).toContainElement(tenantIdInput);
  });

  it("renders deployment guidance and keeps certificate generation functional", async () => {
    // When
    const view = await render(<Harness />);

    // Then
    expect(document.querySelectorAll("ol > li")).toHaveLength(6);
    expect(
      view.getByRole("link", { name: "Deploy to Azure" }).element(),
    ).toHaveAttribute(
      "href",
      "https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fdocs.prowler.com%2Fassets%2Ftemplates%2Fazure%2Fprowler-scan.json",
    );
    expect(
      view.getByRole("link", { name: "Open template" }).element(),
    ).toHaveAttribute(
      "href",
      "https://docs.prowler.com/assets/templates/azure/prowler-scan.json",
    );

    await view.getByRole("button", { name: "Generate certificate" }).click();
    await vi.waitFor(
      () => {
        expect(
          view.getByText(/Downloaded prowler-cert\.cer/).element(),
        ).toBeVisible();
      },
      { timeout: 20_000 },
    );
    expect(view.getByRole("status").element()).toHaveTextContent(
      /Downloaded prowler-cert\.cer/,
    );
    const bundle = view
      .getByRole("textbox", {
        name: "Certificate and Private Key Bundle (Base64)",
      })
      .element() as HTMLTextAreaElement;
    expect(bundle.value.length).toBeGreaterThan(100);
  });
});
