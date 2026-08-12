"use client";

import Link from "next/link";
import { useState } from "react";
import { Control, useFormContext } from "react-hook-form";

import {
  WizardInputField,
  WizardTextareaField,
} from "@/components/providers/workflow/forms/fields";
import { Button } from "@/components/shadcn";
import {
  downloadPublicCertificateFile,
  generateProwlerCertificate,
} from "@/lib/azure-cert-generator";
import { getAzureDeploymentQuickLink } from "@/lib/external-urls";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { AzureCertificateCredentials } from "@/types";

export const AzureCertificateCredentialsForm = ({
  control,
}: {
  control: Control<AzureCertificateCredentials>;
}) => {
  // The Deploy-to-Azure link is a plain constant today: unlike the AWS
  // organisation link, it does not need any wizard-collected value in the
  // URL (subscription selection happens inside the Portal deployment blade).
  // If Prowler ever needs to pin the deployment to a specific subscription
  // or region, thread that value through `getAzureDeploymentQuickLink` here.
  const deployToAzureUrl = getAzureDeploymentQuickLink();

  // Feedback state for the in-browser certificate generator. Kept local
  // because the values only matter to this component — nothing else in the
  // wizard needs to know that the user opted for auto-generation.
  const [isGeneratingCert, setIsGeneratingCert] = useState(false);
  const [generatorError, setGeneratorError] = useState<string | null>(null);
  const [generatedThumbprint, setGeneratedThumbprint] = useState<string | null>(
    null,
  );
  const { setValue } = useFormContext<AzureCertificateCredentials>();

  const handleGenerateCertificate = async () => {
    setGeneratorError(null);
    setGeneratedThumbprint(null);
    setIsGeneratingCert(true);
    try {
      const result = await generateProwlerCertificate();
      // Auto-fill the private key textarea with the ready-to-paste bundle so
      // the user does not need to touch the field manually. `shouldValidate`
      // clears the "Certificate Private Key is required" error immediately.
      setValue(
        ProviderCredentialFields.CERTIFICATE_CONTENT,
        result.privateKeyBundleBase64Pem,
        { shouldValidate: true, shouldDirty: true, shouldTouch: true },
      );
      // Hand the public certificate to the user as a file: they upload it to
      // the Bicep `Certificate Base64` parameter in the Azure Portal.
      downloadPublicCertificateFile(result.publicCertificateBase64Der);
      setGeneratedThumbprint(result.thumbprintHex);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Failed to generate the certificate in-browser. Fall back to the openssl or PowerShell instructions in the guide.";
      setGeneratorError(message);
    } finally {
      setIsGeneratingCert(false);
    }
  };

  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-text-neutral-primary leading-9 font-bold">
          Certificate Authentication (Recommended)
        </div>
        <div className="text-text-neutral-tertiary text-sm">
          The Deploy to Azure quick-start opens the Azure Portal with the
          Prowler Bicep template pre-loaded to provision the App Registration /
          Service Principal and read-only roles. Paste the resulting credentials
          below when the deployment finishes.
        </div>
      </div>
      <div className="flex flex-col items-start gap-1">
        <Button variant="link" size="link-sm" asChild>
          <a href={deployToAzureUrl} target="_blank" rel="noopener noreferrer">
            Deploy to Azure
          </a>
        </Button>
        <p className="text-text-neutral-tertiary text-xs">
          After deployment, copy <strong>Tenant ID</strong> and{" "}
          <strong>Application ID</strong> from the deployment outputs. The
          certificate private key you generated locally goes in the
          &ldquo;Certificate Private Key&rdquo; field below.
        </p>
      </div>
      <div className="border-content-neutral-tertiary flex flex-col items-start gap-2 rounded-md border border-dashed p-3">
        <div className="text-text-neutral-primary text-sm font-semibold">
          Don&apos;t have a certificate yet?
        </div>
        <p className="text-text-neutral-tertiary text-xs">
          Generate a self-signed X.509 certificate right in your browser.
          <strong>
            {" "}
            The certificate and private key are generated locally
          </strong>
          . The base64-encoded certificate/private-key bundle goes into the
          field below and is submitted with the rest of the form. The public
          certificate downloads as a text file for you to paste into the Bicep{" "}
          <code>Certificate Base64</code> parameter in the Portal.
        </p>
        <Button
          type="button"
          variant="default"
          size="sm"
          onClick={handleGenerateCertificate}
          disabled={isGeneratingCert}
        >
          {isGeneratingCert ? "Generating…" : "Generate certificate for me"}
        </Button>
        {generatorError && (
          <p className="text-text-error-primary text-xs">{generatorError}</p>
        )}
        {generatedThumbprint && (
          <p className="text-text-success-primary text-xs">
            Done. Certificate SHA-1 thumbprint:{" "}
            <code>{generatedThumbprint}</code>. Downloaded{" "}
            <code>prowler-cert-base64.txt</code> — paste its contents into the
            Bicep <code>Certificate Base64</code> parameter, then keep filling
            the fields below.
          </p>
        )}
      </div>
      <WizardInputField
        control={control}
        name="tenant_id"
        type="text"
        label="Tenant ID"
        labelPlacement="inside"
        placeholder="Enter the Tenant ID"
        variant="bordered"
        isRequired
      />
      <WizardInputField
        control={control}
        name="client_id"
        type="text"
        label="Client ID"
        labelPlacement="inside"
        placeholder="Enter the Client ID"
        variant="bordered"
        isRequired
      />
      <WizardTextareaField
        control={control}
        name="certificate_content"
        label="Certificate Private Key (Base64)"
        labelPlacement="inside"
        placeholder="Paste the base64-encoded private key that pairs with the certificate deployed to Entra ID"
        variant="bordered"
        isRequired
        minRows={4}
      />
      <p className="text-text-neutral-tertiary text-sm">
        This is the <strong>base64-encoded private key</strong> that matches the
        certificate uploaded to Entra ID by the Bicep template (not the public
        certificate, and not the thumbprint). Use the{" "}
        <em>Generate certificate for me</em> button above, or follow the manual
        openssl / PowerShell instructions in the{" "}
        <Link
          href="https://docs.prowler.com/user-guide/providers/azure/authentication#certificate-authentication"
          target="_blank"
          rel="noopener noreferrer"
          className="text-button-tertiary p-0 text-sm"
        >
          certificate generation guide
        </Link>
        .
      </p>
    </>
  );
};
