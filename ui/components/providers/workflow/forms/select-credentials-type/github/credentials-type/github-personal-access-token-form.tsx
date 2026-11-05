"use client";

import { Control } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Button } from "@/components/shadcn";
import {
  buildGitHubPersonalAccessTokenOrgUrl,
  PRECONFIGURED_CREDENTIAL_URLS,
} from "@/lib/external-urls";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

interface GitHubPersonalAccessTokenFormProps {
  control: Control<any>;
  // GitHub identifier entered in the previous wizard step. When it names an
  // organization, it flows into the org-scoped token URL as `target_name` so
  // GitHub pre-selects the right Resource Owner and surfaces the org-only
  // permissions (`organization_administration`, `members`). When absent, only
  // the personal-repositories link is shown.
  providerUid?: string;
}

export const GitHubPersonalAccessTokenForm = ({
  control,
  providerUid,
}: GitHubPersonalAccessTokenFormProps) => {
  const trimmedProviderUid = providerUid?.trim();

  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-text-neutral-primary leading-9 font-bold">
          Connect via Personal Access Token
        </div>
        <div className="text-text-neutral-tertiary text-sm">
          Please provide your GitHub personal access token.
        </div>
      </div>
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.PERSONAL_ACCESS_TOKEN}
        type="password"
        label="Personal Access Token"
        labelPlacement="inside"
        placeholder="Enter your GitHub personal access token"
        variant="bordered"
        isRequired
      />
      <div className="flex flex-col items-start gap-1">
        <Button variant="link" size="link-sm" asChild>
          <a
            href={
              PRECONFIGURED_CREDENTIAL_URLS.GITHUB_PERSONAL_ACCESS_TOKEN_USER
            }
            target="_blank"
            rel="noopener noreferrer"
          >
            Create a pre-configured token for personal repositories
          </a>
        </Button>
        {trimmedProviderUid && (
          <Button variant="link" size="link-sm" asChild>
            <a
              href={buildGitHubPersonalAccessTokenOrgUrl(trimmedProviderUid)}
              target="_blank"
              rel="noopener noreferrer"
            >
              {`Create a pre-configured token for organization ${trimmedProviderUid}`}
            </a>
          </Button>
        )}
      </div>
    </>
  );
};
