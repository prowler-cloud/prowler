"use client";

import { Control } from "react-hook-form";

import { CustomInput, CustomTextarea } from "@/components/ui/custom";
import { CustomLink } from "@/components/ui/custom/custom-link";
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
      <CustomInput
        control={control}
        name="tenant_id"
        type="text"
        label="Tenant ID"
        labelPlacement="inside"
        placeholder="Enter the Tenant ID"
        variant="bordered"
        isRequired
      />
      <CustomInput
        control={control}
        name="client_id"
        type="text"
        label="Client ID"
        labelPlacement="inside"
        placeholder="Enter the Client ID"
        variant="bordered"
        isRequired
      />
      <CustomTextarea
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
        <CustomLink
          href="https://docs.prowler.com/user-guide/providers/microsoft365/authentication#generate-the-certificate"
          size="sm"
        >
          certificate generation guide
        </CustomLink>
        .
      </p>
    </>
  );
};
