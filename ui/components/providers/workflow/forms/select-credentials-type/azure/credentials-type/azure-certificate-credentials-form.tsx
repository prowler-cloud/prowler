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

      <div className="flex flex-col gap-4">
        <section className="border-content-neutral-tertiary flex flex-col gap-3 rounded-md border p-4">
          <h3 className="text-text-neutral-primary text-sm font-semibold">
            Create the application
          </h3>
          <ol className="flex list-decimal flex-col gap-3 pl-5 text-sm">
            <li>
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
                <span>
                  Register an Azure application, then copy its Directory
                  (tenant) ID and Application (client) ID.
                </span>
                <Button variant="link" size="link-sm" asChild>
                  <a
                    href={AZURE_PORTAL_NEW_APP_REGISTRATION_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <ExternalLink className="size-3.5 shrink-0" />
                    <span>Open Azure</span>
                  </a>
                </Button>
              </div>
            </li>
            <li>
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
                <span>
                  Generate the certificate. The private bundle is filled below
                  and submitted to Prowler only when you connect.
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
              <div role="status" aria-live="polite" aria-atomic="true">
                {isGeneratingCert && (
                  <p className="text-text-neutral-tertiary mt-2 text-xs">
                    Generating certificate...
                  </p>
                )}
                {generatorError && (
                  <p className="text-text-error-primary mt-2 text-xs">
                    {generatorError}
                  </p>
                )}
                {generatedThumbprint && (
                  <p className="text-text-success-primary mt-2 text-xs">
                    Downloaded <code>prowler-cert.cer</code>. Thumbprint{" "}
                    <code>{generatedThumbprint}</code>
                  </p>
                )}
              </div>
            </li>
          </ol>
        </section>

        <section className="border-content-neutral-tertiary flex flex-col gap-3 rounded-md border p-4">
          <h3 className="text-text-neutral-primary text-sm font-semibold">
            Configure access
          </h3>
          <ol
            start={3}
            className="flex list-decimal flex-col gap-3 pl-5 text-sm"
          >
            <li>
              Upload <code>prowler-cert.cer</code> under Certificates &amp;
              secrets. Add Microsoft Graph application permissions:
              AuditLog.Read.All, Directory.Read.All (or Domain.Read.All), and
              Policy.Read.All. Then grant admin consent.
            </li>
            <li>
              Copy the Service Principal Object ID from{" "}
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
            </li>
          </ol>
        </section>

        <section className="border-content-neutral-tertiary flex flex-col gap-3 rounded-md border p-4">
          <h3 className="text-text-neutral-primary text-sm font-semibold">
            Deploy and connect
          </h3>
          <ol
            start={5}
            className="flex list-decimal flex-col gap-3 pl-5 text-sm"
          >
            <li>
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
                <span>
                  Deploy subscription RBAC with the Service Principal Object ID.
                  The template creates ProwlerRole and assigns Reader and
                  ProwlerRole; it does not create Entra resources.
                </span>
                <Button variant="default" size="sm" asChild>
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
              <p className="text-text-neutral-tertiary mt-2 text-xs">
                Manual deployment: in Azure Portal, use Build your own template
                in the editor.{" "}
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
              Return to Prowler and complete the fields below. The generated
              certificate bundle is already filled.
            </li>
          </ol>
        </section>
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
