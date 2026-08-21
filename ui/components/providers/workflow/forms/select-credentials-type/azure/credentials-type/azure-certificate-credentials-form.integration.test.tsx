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
    const bundle = view
      .getByRole("textbox", {
        name: "Certificate and Private Key Bundle (Base64)",
      })
      .element() as HTMLTextAreaElement;
    expect(bundle.value.length).toBeGreaterThan(100);
  });
});
