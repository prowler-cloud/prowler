import Link from "next/link";
import { Control } from "react-hook-form";

import { InfoIcon } from "@/components/icons";
import { CustomInput } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { M365Credentials } from "@/types";

export const M365ServicePrincipalUserForm = ({
  control,
}: {
  control: Control<M365Credentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md font-bold leading-9 text-default-foreground">
          Service Principal + User Credentials
        </div>
        <div className="text-sm text-default-500">
          Connect using Service Principal credentials combined with user authentication for PowerShell modules.
        </div>
      </div>

      <div className="flex items-center rounded-lg border border-system-info bg-system-info-medium p-3 text-sm dark:text-default-300">
        <InfoIcon className="mr-2 inline h-4 w-4 flex-shrink-0" />
        <div className="text-xs">
          <p className="font-extrabold mb-2">This method provides:</p>
          <ul className="list-disc list-inside space-y-1">
            <li>Service Principal authentication for Microsoft Graph APIs</li>
            <li>User credentials for PowerShell modules access</li>
            <li>Complete M365 service coverage</li>
          </ul>
        </div>
      </div>

      <span className="text-xs font-bold text-default-500">Service Principal Information</span>

      <CustomInput
        control={control}
        name={ProviderCredentialFields.CLIENT_ID}
        type="text"
        label="Client ID"
        labelPlacement="inside"
        placeholder="Enter the Client ID"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors[ProviderCredentialFields.CLIENT_ID]}
      />

      <CustomInput
        control={control}
        name={ProviderCredentialFields.CLIENT_SECRET}
        type="password"
        label="Client Secret"
        labelPlacement="inside"
        placeholder="Enter the Client Secret"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors[ProviderCredentialFields.CLIENT_SECRET]}
      />

      <CustomInput
        control={control}
        name={ProviderCredentialFields.TENANT_ID}
        type="text"
        label="Tenant ID"
        labelPlacement="inside"
        placeholder="Enter the Tenant ID"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors[ProviderCredentialFields.TENANT_ID]}
      />

      <span className="text-xs font-bold text-default-500">User Credentials for PowerShell</span>

      <CustomInput
        control={control}
        name={ProviderCredentialFields.USER}
        type="text"
        label="User"
        labelPlacement="inside"
        placeholder="Enter the User (e.g., user@company.onmicrosoft.com)"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors[ProviderCredentialFields.USER]}
      />

      <CustomInput
        control={control}
        name={ProviderCredentialFields.PASSWORD}
        type="password"
        label="Password"
        labelPlacement="inside"
        placeholder="Enter the Password"
        variant="bordered"
        isRequired
        isInvalid={!!control._formState.errors[ProviderCredentialFields.PASSWORD]}
      />

      <div className="flex items-center rounded-lg border border-system-warning bg-system-warning-medium p-2 text-sm dark:text-default-300">
        <InfoIcon className="mr-2 inline h-4 w-4 flex-shrink-0" />
        <p className="text-xs font-extrabold">
          By September 2025, User Authentication will be deprecated.
        </p>
      </div>

      <p className="text-sm text-default-500">
        For more information on setting up authentication, see the{" "}
        <Link
          href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/microsoft365/getting-started-m365/"
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-primary hover:underline"
        >
          M365 setup documentation
        </Link>
        .
      </p>
    </>
  );
};
