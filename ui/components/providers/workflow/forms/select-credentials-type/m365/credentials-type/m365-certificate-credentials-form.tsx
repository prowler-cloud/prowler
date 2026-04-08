"use client";

import Link from "next/link";
import { Control } from "react-hook-form";

import {
  WizardInputField,
  WizardTextareaField,
} from "@/components/providers/workflow/forms/fields";
import { M365CertificateCredentials } from "@/types";

export const M365CertificateCredentialsForm = ({
  control,
}: {
  control: Control<M365CertificateCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          App Certificate Credentials
        </div>
        <div className="text-default-500 text-sm">
          Please provide your Microsoft 365 application credentials with
          certificate authentication.
        </div>
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
        label="Certificate Content"
        labelPlacement="inside"
        placeholder="Enter the base64 encoded certificate content"
        variant="bordered"
        isRequired
        minRows={4}
      />
      <p className="text-default-500 text-sm">
        The certificate content must be base64 encoded from an unsigned
        certificate. For detailed instructions on how to generate and encode
        your certificate, please refer to the{" "}
        <Link
          href="https://docs.prowler.com/user-guide/providers/microsoft365/authentication#generate-the-certificate"
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
