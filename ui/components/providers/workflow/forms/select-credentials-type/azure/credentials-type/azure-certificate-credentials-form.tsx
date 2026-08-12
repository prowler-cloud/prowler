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

export const AzureCertificateCredentialsForm = ({
  control,
}: {
  control: Control<AzureCertificateCredentials>;
}) => {
  // The Deploy-to-Azure link is a plain constant today: unlike the AWS
  // organisation link, it does not need any wizard-collected value in the
  // URL (subscription and the service principal Object ID are filled inside
  // the Portal deployment blade). Prefilling the SP Object ID via the URL
  // would need the Portal's uiFormDefinitionUri machinery, which is more
  // moving parts than the copy-paste we already ask the user to do.
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
      // the App Registration's Certificates blade in the Azure Portal.
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
          Prowler authenticates against Azure with an X.509 certificate bound
          to an Entra ID App Registration. The setup is a two-step flow: create
          the App Registration and upload the certificate through the Azure
          Portal, then click <strong>Deploy to Azure</strong> below to grant
          that App Registration the read-only permissions Prowler needs on the
          subscription.
        </div>
      </div>
      <div className="border-content-warning-tertiary bg-content-warning-tertiary/10 flex flex-col gap-2 rounded-md border p-3">
        <div className="text-text-neutral-primary text-sm font-semibold">
          Before you start
        </div>
        <p className="text-text-neutral-tertiary text-xs">
          Your Azure account needs permissions in <em>two</em> separate systems.
          The wizard cannot work around a missing role — request them from your
          Azure administrator if needed:
        </p>
        <ul className="text-text-neutral-tertiary ml-4 list-disc space-y-1 text-xs">
          <li>
            <strong>Microsoft Entra ID</strong>:{" "}
            <strong>Application Administrator</strong>,{" "}
            <strong>Cloud Application Administrator</strong>, or{" "}
            <strong>Global Administrator</strong> — needed to create the App
            Registration and upload the certificate in step 1. Not required if
            your tenant already allows all users to register applications
            (Entra ID → Users → User settings).
          </li>
          <li>
            <strong>Azure RBAC</strong>: <strong>Owner</strong> on the target
            subscription — needed by <em>Deploy to Azure</em> in step 3 to
            assign the <code>Reader</code> and custom <code>ProwlerRole</code>{" "}
            roles.
          </li>
        </ul>
      </div>
      <ol className="border-content-neutral-tertiary flex flex-col gap-4 rounded-md border p-4">
        <li className="flex flex-col gap-2">
          <div className="text-text-neutral-primary text-sm font-semibold">
            1. Create the App Registration in Azure
          </div>
          <p className="text-text-neutral-tertiary text-xs">
            Open the Portal in a new tab, sign in to the tenant you want
            Prowler to scan, and register a new application. Any name works
            (e.g. <code>Prowler</code>); keep the default single-tenant
            audience and no redirect URI.
          </p>
          <Button variant="link" size="link-sm" asChild>
            <a
              href={AZURE_PORTAL_NEW_APP_REGISTRATION_URL}
              target="_blank"
              rel="noopener noreferrer"
            >
              Open Azure Portal → New App Registration
            </a>
          </Button>
        </li>
        <li className="flex flex-col gap-2">
          <div className="text-text-neutral-primary text-sm font-semibold">
            2. Attach a certificate to that App Registration
          </div>
          <p className="text-text-neutral-tertiary text-xs">
            In your new App Registration, open{" "}
            <em>Certificates &amp; secrets → Certificates → Upload
            certificate</em> and upload the public certificate file
            (<code>.cer</code>). The button below generates the keypair in your
            browser — the private key is auto-filled into the form below and
            the public certificate downloads as a text file you decode and
            upload.
          </p>
          <div className="border-content-neutral-tertiary flex flex-col items-start gap-2 rounded-md border border-dashed p-3">
            <p className="text-text-neutral-tertiary text-xs">
              <strong>The certificate never leaves your browser.</strong>{" "}
              Prowler generates the keypair client-side and only receives the
              private half; the public half goes to Entra ID via the manual
              upload.
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
              <p className="text-text-error-primary text-xs">
                {generatorError}
              </p>
            )}
            {generatedThumbprint && (
              <p className="text-text-success-primary text-xs">
                Done. Certificate SHA-1 thumbprint:{" "}
                <code>{generatedThumbprint}</code>. Downloaded{" "}
                <code>prowler-cert-base64.txt</code> — decode it back to a{" "}
                <code>.cer</code> with{" "}
                <code>base64 -D -i prowler-cert-base64.txt -o prowler.cer</code>{" "}
                and upload <code>prowler.cer</code> in the Portal.
              </p>
            )}
            <p className="text-text-neutral-tertiary text-xs">
              Prefer the command line? See the{" "}
              <Link
                href="https://docs.prowler.com/user-guide/providers/azure/authentication#certificate-authentication"
                target="_blank"
                rel="noopener noreferrer"
                className="text-button-tertiary p-0 text-sm"
              >
                openssl / PowerShell instructions
              </Link>
              .
            </p>
          </div>
        </li>
        <li className="flex flex-col gap-2">
          <div className="text-text-neutral-primary text-sm font-semibold">
            3. Grant the App Registration read access to your subscription
          </div>
          <p className="text-text-neutral-tertiary text-xs">
            You need the App Registration&apos;s <strong>Service Principal
            Object ID</strong> — not the same as the App Registration&apos;s
            Object ID. Find it in{" "}
            <Link
              href={AZURE_PORTAL_ENTERPRISE_APPLICATIONS_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-button-tertiary p-0 text-sm"
            >
              Entra ID → Enterprise applications
            </Link>{" "}
            → search for the app you just created → <em>Overview → Object
            ID</em>. Then click Deploy to Azure below and paste that Object ID
            when the Portal asks.
          </p>
          <Button variant="link" size="link-sm" asChild>
            <a
              href={deployToAzureUrl}
              target="_blank"
              rel="noopener noreferrer"
            >
              Deploy to Azure
            </a>
          </Button>
        </li>
        <li className="flex flex-col gap-2">
          <div className="text-text-neutral-primary text-sm font-semibold">
            4. Come back here and fill the fields below
          </div>
          <p className="text-text-neutral-tertiary text-xs">
            Copy the <strong>Tenant ID</strong> from Entra ID → Overview,
            the <strong>Application (client) ID</strong> from your App
            Registration&apos;s Overview page, and paste both into the fields
            below. The private key field is already pre-filled from step 2 (or
            paste your own base64-encoded PEM bundle / PKCS#12 if you
            generated the keypair manually).
          </p>
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
        placeholder="Paste the base64-encoded private key that pairs with the certificate uploaded to Entra ID"
        variant="bordered"
        isRequired
        minRows={4}
      />
      <p className="text-text-neutral-tertiary text-sm">
        This is the <strong>base64-encoded private key</strong> that matches
        the certificate you uploaded to Entra ID in step 2 (not the public
        certificate, and not the thumbprint). Use the{" "}
        <em>Generate certificate for me</em> button in step 2, or follow the
        manual openssl / PowerShell instructions in the{" "}
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
