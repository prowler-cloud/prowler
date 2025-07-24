import { Control } from "react-hook-form";

import { CustomInput, CustomTextarea } from "@/components/ui/custom";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { GitHubCredentials } from "@/types";

export const GitHubCredentialsForm = ({
  control,
  via,
}: {
  control: Control<GitHubCredentials>;
  via?: string;
}) => {
  const renderHeader = (description: string) => (
    <div className="flex flex-col">
      <h2 className="text-md font-bold leading-9 text-default-foreground">
        Connect via Credentials
      </h2>
      <div className="text-sm text-default-500">{description}</div>
    </div>
  );

  const renderPersonalAccessTokenFields = () => (
    <div className="space-y-3">
      <div className="border-b border-divider pb-2">
        <h3 className="text-sm font-semibold text-default-foreground">
          Personal Access Token
        </h3>
        <p className="text-sm text-default-500">
          Use a personal access token for individual user authentication
        </p>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.PERSONAL_ACCESS_TOKEN}
        type="password"
        label="Personal Access Token"
        labelPlacement="inside"
        placeholder="Enter the Personal Access Token"
        variant="bordered"
        isRequired
        isInvalid={
          !!control._formState.errors[
            ProviderCredentialFields.PERSONAL_ACCESS_TOKEN
          ]
        }
      />
    </div>
  );

  const renderOAuthAppTokenFields = () => (
    <div className="space-y-3">
      <div className="border-b border-divider pb-2">
        <h3 className="text-sm font-semibold text-default-foreground">
          OAuth App Token
        </h3>
        <p className="text-sm text-default-500">
          Use an OAuth app token for application-level authentication
        </p>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.OAUTH_APP_TOKEN}
        type="password"
        label="OAuth App Token"
        labelPlacement="inside"
        placeholder="Enter the OAuth App Token"
        variant="bordered"
        isRequired
        isInvalid={
          !!control._formState.errors[ProviderCredentialFields.OAUTH_APP_TOKEN]
        }
      />
    </div>
  );

  const renderGitHubAppFields = () => (
    <div className="space-y-3">
      <div className="border-b border-divider pb-2">
        <h3 className="text-sm font-semibold text-default-foreground">
          GitHub App
        </h3>
        <p className="text-sm text-default-500">
          Use GitHub App credentials (both App ID and Private Key are required)
        </p>
      </div>
      <CustomInput
        control={control}
        name={ProviderCredentialFields.GITHUB_APP_ID}
        label="GitHub App ID"
        labelPlacement="inside"
        placeholder="Enter the GitHub App ID"
        variant="bordered"
        isRequired
        isInvalid={
          !!control._formState.errors[ProviderCredentialFields.GITHUB_APP_ID]
        }
      />
      <CustomTextarea
        control={control}
        name={ProviderCredentialFields.GITHUB_APP_KEY}
        label="GitHub App Private Key"
        labelPlacement="inside"
        placeholder="Paste your GitHub App Private Key content here"
        variant="bordered"
        minRows={10}
        isRequired
        isInvalid={
          !!control._formState.errors[ProviderCredentialFields.GITHUB_APP_KEY]
        }
      />
    </div>
  );

  const renderAllOptions = () => (
    <>
      {renderHeader(
        "Choose one of the following authentication methods for your GitHub credentials:",
      )}

      {/* Option 1: Personal Access Token */}
      <div className="space-y-3">
        <div className="border-b border-divider pb-2">
          <h3 className="text-sm font-semibold text-default-foreground">
            Option 1: Personal Access Token
          </h3>
          <p className="text-sm text-default-500">
            Use a personal access token for individual user authentication
          </p>
        </div>
        <CustomInput
          control={control}
          name={ProviderCredentialFields.PERSONAL_ACCESS_TOKEN}
          type="password"
          label="Personal Access Token"
          labelPlacement="inside"
          placeholder="Enter the Personal Access Token"
          variant="bordered"
          isRequired={false}
          isInvalid={
            !!control._formState.errors[
              ProviderCredentialFields.PERSONAL_ACCESS_TOKEN
            ]
          }
        />
      </div>

      {/* Option 2: OAuth App Token */}
      <div className="space-y-3">
        <div className="border-b border-divider pb-2">
          <h3 className="text-sm font-semibold text-default-foreground">
            Option 2: OAuth App Token
          </h3>
          <p className="text-sm text-default-500">
            Use an OAuth app token for application-level authentication
          </p>
        </div>
        <CustomInput
          control={control}
          name={ProviderCredentialFields.OAUTH_APP_TOKEN}
          type="password"
          label="OAuth App Token"
          labelPlacement="inside"
          placeholder="Enter the OAuth App Token"
          variant="bordered"
          isRequired={false}
          isInvalid={
            !!control._formState.errors[
              ProviderCredentialFields.OAUTH_APP_TOKEN
            ]
          }
        />
      </div>

      {/* Option 3: GitHub App */}
      <div className="space-y-3">
        <div className="border-b border-divider pb-2">
          <h3 className="text-sm font-semibold text-default-foreground">
            Option 3: GitHub App
          </h3>
          <p className="text-sm text-default-500">
            Use GitHub App credentials (both App ID and Private Key are
            required)
          </p>
        </div>
        <CustomInput
          control={control}
          name={ProviderCredentialFields.GITHUB_APP_ID}
          label="GitHub App ID"
          labelPlacement="inside"
          placeholder="Enter the GitHub App ID"
          variant="bordered"
          isRequired={false}
          isInvalid={
            !!control._formState.errors[ProviderCredentialFields.GITHUB_APP_ID]
          }
        />
        <CustomTextarea
          control={control}
          name={ProviderCredentialFields.GITHUB_APP_KEY}
          label="GitHub App Private Key"
          labelPlacement="inside"
          placeholder="Paste your GitHub App Private Key content here"
          variant="bordered"
          minRows={8}
          isRequired={false}
          isInvalid={
            !!control._formState.errors[ProviderCredentialFields.GITHUB_APP_KEY]
          }
        />
      </div>
    </>
  );

  // If via parameter is provided, show only the selected method
  if (via) {
    return (
      <>
        {renderHeader(
          "Enter your GitHub credentials for the selected authentication method",
        )}

        {via === "personal_access_token" && renderPersonalAccessTokenFields()}
        {via === "oauth_app_token" && renderOAuthAppTokenFields()}
        {via === "github_app" && renderGitHubAppFields()}
      </>
    );
  }

  // If no via parameter, show all options (fallback behavior)
  return renderAllOptions();
};
