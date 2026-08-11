import { render, screen } from "@testing-library/react";
import { FormProvider, useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import { AzureCertificateCredentials } from "@/types";

import { AzureCertificateCredentialsForm } from "./azure-certificate-credentials-form";

// Wraps the form in a react-hook-form context so the WizardInputField and
// WizardTextareaField mount without exploding. We are testing the Deploy to
// Azure link and the field structure, not the input controls themselves.
const Harness = () => {
  const form = useForm<AzureCertificateCredentials>();
  return (
    <FormProvider {...form}>
      <AzureCertificateCredentialsForm control={form.control} />
    </FormProvider>
  );
};

describe("AzureCertificateCredentialsForm", () => {
  it("renders the Deploy to Azure link with the Portal custom-deployment URL and safe target attributes", () => {
    // Given
    render(<Harness />);

    // When
    const link = screen.getByRole("link", { name: /deploy to azure/i });

    // Then
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");

    const href = link.getAttribute("href") ?? "";
    expect(
      href.startsWith(
        "https://portal.azure.com/#create/Microsoft.Template/uri/",
      ),
    ).toBe(true);
    // The Bicep template URL must be percent-encoded exactly once into the
    // fragment; asserting on the encoded slashes guards against a future
    // refactor that swaps `encodeURIComponent` for a helper that leaves them
    // raw and breaks the Portal parser.
    expect(href).toContain(
      "https%3A%2F%2Fprowler-cloud-public.s3.eu-west-1.amazonaws.com%2Fpermissions%2Ftemplates%2Fazure%2Fbicep%2Fprowler-scan.json",
    );
  });

  it("keeps the certificate generation docs link pointing at the Azure authentication doc", () => {
    // Given
    render(<Harness />);

    // When
    const docsLink = screen.getByRole("link", {
      name: /certificate generation guide/i,
    });

    // Then
    expect(docsLink).toHaveAttribute(
      "href",
      "https://docs.prowler.com/user-guide/providers/azure/authentication#certificate-authentication",
    );
    expect(docsLink).toHaveAttribute("target", "_blank");
    expect(docsLink).toHaveAttribute("rel", "noopener noreferrer");
  });
});
