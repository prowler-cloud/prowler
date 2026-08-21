"use client";

import { ExternalLink } from "lucide-react";
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
import {
  getAzureDeploymentQuickLink,
  PROWLER_AZURE_ARM_TEMPLATE_URL,
} from "@/lib/external-urls";
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
          Requires permission to create App Registrations and grant Microsoft
          Graph admin consent, plus <strong>Owner</strong> on the subscription.{" "}
          <Link
            href={DOCS_CERT_GENERATION_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="text-button-tertiary inline-flex items-center gap-2"
          >
            <ExternalLink className="size-3.5 shrink-0" />
            <span>Full guide</span>
          </Link>
          .
        </div>
      </div>

      <ol className="border-content-neutral-tertiary flex flex-col gap-3 rounded-md border p-4 text-sm">
        <li className="flex items-center justify-between gap-3">
          <span>
            <strong>1.</strong> Create an App Registration. Copy its Directory
            (tenant) ID and Application (client) ID.
          </span>
          <Button variant="link" size="link-sm" asChild>
            <a
              href={AZURE_PORTAL_NEW_APP_REGISTRATION_URL}
              target="_blank"
              rel="noopener noreferrer"
            >
              <ExternalLink className="size-3.5 shrink-0" />
              <span>New App Registration</span>
            </a>
          </Button>
        </li>

        <li className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-3">
            <span>
              <strong>2.</strong> Generate the certificate bundle and upload the
              public prowler-cert.cer file under Certificates &amp; secrets. The
              private bundle is filled below and is submitted to Prowler only
              when you connect.
            </span>
            <Button
              type="button"
              variant="default"
              size="sm"
              onClick={handleGenerateCertificate}
              disabled={isGeneratingCert}
            >
              {isGeneratingCert ? "Generating..." : "Generate certificate"}
            </Button>
          </div>
          {generatorError && (
            <p className="text-text-error-primary text-xs">{generatorError}</p>
          )}
          {generatedThumbprint && (
            <p className="text-text-success-primary text-xs">
              Downloaded <code>prowler-cert.cer</code>. Thumbprint{" "}
              <code>{generatedThumbprint}</code>
            </p>
          )}
        </li>

        <li>
          <strong>3.</strong> Add Microsoft Graph application permissions:
          AuditLog.Read.All, Directory.Read.All (or Domain.Read.All), and
          Policy.Read.All. Then grant admin consent.
        </li>

        <li className="flex items-center justify-between gap-3">
          <span>
            <strong>4.</strong> Copy the Service Principal Object ID from{" "}
            <Link
              href={AZURE_PORTAL_ENTERPRISE_APPLICATIONS_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-button-tertiary inline-flex items-center gap-2"
            >
              <ExternalLink className="size-3.5 shrink-0" />
              <span>Enterprise applications</span>
            </Link>
            .
          </span>
        </li>

        <li className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-3">
            <span>
              <strong>5.</strong> Deploy subscription RBAC with that Service
              Principal Object ID. The template creates ProwlerRole and assigns
              Reader and ProwlerRole; it does not create Entra resources.
            </span>
            <Button variant="link" size="link-sm" asChild>
              <a
                href={deployToAzureUrl}
                target="_blank"
                rel="noopener noreferrer"
              >
                <ExternalLink className="size-3.5 shrink-0" />
                <span>Deploy to Azure</span>
              </a>
            </Button>
          </div>
          <p className="text-text-neutral-tertiary text-xs">
            To deploy the ARM JSON manually, use Azure Portal → Build your own
            template in the editor.{" "}
            <Button variant="link" size="link-sm" asChild>
              <a
                href={PROWLER_AZURE_ARM_TEMPLATE_URL}
                target="_blank"
                rel="noopener noreferrer"
              >
                <ExternalLink className="size-3.5 shrink-0" />
                <span>Open template</span>
              </a>
            </Button>
          </p>
        </li>

        <li>
          <strong>6.</strong> Return to Prowler and connect. Paste the Tenant ID
          and Application Client ID below; the generated certificate bundle is
          already filled.
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
        label="Certificate and Private Key Bundle (Base64)"
        labelPlacement="inside"
        placeholder="Auto-filled by 'Generate certificate', or paste your own"
        variant="bordered"
        isRequired
        minRows={4}
      />
    </>
  );
};
