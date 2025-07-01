import Link from "next/link";
import { Control } from "react-hook-form";

import { InfoIcon } from "@/components/icons";
import { CustomInput } from "@/components/ui/custom";
import { M365Credentials } from "@/types";

export const M365CredentialsForm = ({
  control,
}: {
  control: Control<M365Credentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          Connect via Credentials
        </div>
        <div className="text-sm text-default-500">
          Please provide the information for your Microsoft 365 credentials.
        </div>
      </div>
      <CustomInput
        control={control}
        name="client_id"
        type="text"
        label="Client ID"
        labelPlacement="inside"
        placeholder="Enter the Client ID"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors.client_id}
      />
      <CustomInput
        control={control}
        name="client_secret"
        type="password"
        label="Client Secret"
        labelPlacement="inside"
        placeholder="Enter the Client Secret"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors.client_secret}
      />
      <CustomInput
        control={control}
        name="tenant_id"
        type="text"
        label="Tenant ID"
        labelPlacement="inside"
        placeholder="Enter the Tenant ID"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors.tenant_id}
      />
      <p className="text-sm text-default-500">
        {" "}
        User and password authentication is being deprecated due to
        Microsoft&apos;s on-going MFA enforcement across all tenants (see{" "}
        <Link
          href="https://azure.microsoft.com/en-us/blog/announcing-mandatory-multi-factor-authentication-for-azure-sign-in/"
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-primary hover:underline"
        >
          Microsoft docs
        </Link>
        ).
      </p>

      <div className="flex items-center rounded-lg border border-system-warning bg-system-warning-medium p-2 text-sm dark:text-default-300">
        <InfoIcon className="mr-2 inline h-4 w-4 flex-shrink-0" />
        <p className="text-xs font-extrabold">
          By September 2025, MFA will be mandatory.
        </p>
      </div>
      <p className="text-sm text-default-500">
        Due to that change, you must only{" "}
        <Link
          href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/microsoft365/getting-started-m365/#step-3-configure-your-m365-account"
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-primary hover:underline"
        >
          use application authentication
        </Link>{" "}
        to maintain all Prowler M365 scan capabilities.
      </p>
      <CustomInput
        control={control}
        name="user"
        type="text"
        label="User"
        labelPlacement="inside"
        placeholder="Enter the User"
        variant="bordered"
        isRequired={false}
        isInvalid={!!control._formState.errors.user}
      />
      <CustomInput
        control={control}
        name="password"
        type="password"
        label="Password"
        labelPlacement="inside"
        placeholder="Enter the Password"
        variant="bordered"
        isRequired={false}
        isInvalid={!!control._formState.errors.password}
      />
    </>
  );
};
