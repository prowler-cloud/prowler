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

const AZURE_PORTAL_NEW_APP_REGISTRATION_URL =
  "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/CreateApplicationBlade";

const AZURE_PORTAL_ENTERPRISE_APPLICATIONS_URL =
  "https://portal.azure.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview";

const DOCS_CERT_GENERATION_URL =
  "https://docs.prowler.com/user-guide/providers/azure/authentication#certificate-authentication";

export const AzureCertificateCredentialsForm = ({
  control,
}: {
  control: Control<AzureCertificateCredentials>;
}) => {
  const deployToAzureUrl = getAzureDeploymentQuickLink();

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
      setValue(
        ProviderCredentialFields.CERTIFICATE_CONTENT,
        result.privateKeyBundleBase64Pem,
        { shouldValidate: true, shouldDirty: true, shouldTouch: true },
      );
      downloadPublicCertificateFile(result.publicCertificateBase64Der);
      setGeneratedThumbprint(result.thumbprintHex);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Failed to generate the certificate in-browser. Fall back to openssl / PowerShell.";
      setGeneratorError(message);
    }
    setIsGeneratingCert(false);
  };

  return (
    <>
      <div className="flex flex-col gap-1">
        <div className="text-md text-text-neutral-primary leading-9 font-bold">
          Certificate Authentication (Recommended)
        </div>
        <div className="text-text-neutral-tertiary text-xs">
          Requires <strong>Application Administrator</strong> (Entra ID) and{" "}
          <strong>Owner</strong> (subscription).{" "}
          <Link
            href={DOCS_CERT_GENERATION_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="text-button-tertiary"
          >
            Full guide
          </Link>
          .
        </div>
      </div>

      <ol className="border-content-neutral-tertiary flex flex-col gap-3 rounded-md border p-4 text-sm">
        <li className="flex items-center justify-between gap-3">
          <span>
            <strong>1.</strong> Create the App Registration in Azure.
          </span>
          <Button variant="link" size="link-sm" asChild>
            <a
              href={AZURE_PORTAL_NEW_APP_REGISTRATION_URL}
              target="_blank"
              rel="noopener noreferrer"
            >
              New App Reg ↗
            </a>
          </Button>
        </li>

        <li className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-3">
            <span>
              <strong>2.</strong> Generate a certificate and upload{" "}
              <code>prowler-cert.cer</code> to your App Reg (
              <em>Certificates &amp; secrets</em>).
            </span>
            <Button
              type="button"
              variant="default"
              size="sm"
              onClick={handleGenerateCertificate}
              disabled={isGeneratingCert}
            >
              {isGeneratingCert ? "Generating…" : "Generate cert"}
            </Button>
          </div>
          {generatorError && (
            <p className="text-text-error-primary text-xs">{generatorError}</p>
          )}
          {generatedThumbprint && (
            <p className="text-text-success-primary text-xs">
              Downloaded <code>prowler-cert.cer</code> · thumbprint{" "}
              <code>{generatedThumbprint}</code>
            </p>
          )}
        </li>

        <li className="flex items-center justify-between gap-3">
          <span>
            <strong>3.</strong> Grant read access (needs the SP Object ID from{" "}
            <Link
              href={AZURE_PORTAL_ENTERPRISE_APPLICATIONS_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-button-tertiary"
            >
              Enterprise applications
            </Link>
            ).
          </span>
          <Button variant="link" size="link-sm" asChild>
            <a
              href={deployToAzureUrl}
              target="_blank"
              rel="noopener noreferrer"
            >
              Deploy to Azure ↗
            </a>
          </Button>
        </li>

        <li>
          <strong>4.</strong> Paste the IDs below (Tenant ID and Application
          (client) ID from your App Reg&apos;s Overview).
        </li>
      </ol>

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
        placeholder="Auto-filled by 'Generate cert', or paste your own"
        variant="bordered"
        isRequired
        minRows={4}
      />
    </>
  );
};
