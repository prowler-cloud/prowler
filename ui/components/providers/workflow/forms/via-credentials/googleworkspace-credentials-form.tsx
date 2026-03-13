import { Control } from "react-hook-form";

import { CustomInput, CustomTextarea } from "@/components/ui/custom";
import { GoogleWorkspaceCredentials } from "@/types";

export const GoogleWorkspaceCredentialsForm = ({
  control,
}: {
  control: Control<GoogleWorkspaceCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-default-foreground leading-9 font-bold">
          Connect via Service Account
        </div>
        <div className="text-default-500 text-sm">
          Provide your Google Workspace Customer ID, Service Account JSON, and
          the admin email to impersonate.
        </div>
      </div>
      <div className="border-default-200 rounded-lg border bg-default-50 p-3 text-xs text-default-600">
        <div className="mb-1 font-semibold">How to find your Customer ID:</div>
        <ol className="ml-4 list-decimal space-y-1">
          <li>
            Sign in to your{" "}
            <a
              href="https://admin.google.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:text-primary-600 underline"
            >
              Google Admin console
            </a>
          </li>
          <li>Go to Account → Account settings</li>
          <li>
            Find your Customer ID in the &quot;Profile&quot; section (starts
            with &apos;C&apos;)
          </li>
        </ol>
      </div>
      <CustomInput
        control={control}
        name="customer_id"
        type="text"
        label="Customer ID"
        labelPlacement="inside"
        placeholder="Customer ID starts with 'C' (e.g., C01234abc)"
        variant="bordered"
        isRequired
      />
      <CustomTextarea
        control={control}
        name="credentials_content"
        label="Service Account JSON"
        labelPlacement="inside"
        placeholder="Paste your Service Account JSON here"
        variant="bordered"
        minRows={10}
        isRequired
      />
      <CustomInput
        control={control}
        name="delegated_user"
        type="email"
        label="Delegated User Email"
        labelPlacement="inside"
        placeholder="admin@example.com"
        variant="bordered"
        isRequired
      />
      <div className="text-default-400 text-xs">
        Credentials never leave your browser unencrypted and are stored as
        secrets in the backend. You can revoke the Service Account from the
        Google Cloud Console anytime if needed.
      </div>
    </>
  );
};
