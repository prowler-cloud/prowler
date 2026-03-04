"use client";

import { Control, Controller } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
import { FormMessage } from "@/components/ui/form";

type RadioGroupGitHubViaCredentialsFormProps = {
  control: Control<any>;
  isInvalid: boolean;
  errorMessage?: string;
  onChange?: (value: string) => void;
};

export const RadioGroupGitHubViaCredentialsTypeForm = ({
  control,
  isInvalid,
  errorMessage,
  onChange,
}: RadioGroupGitHubViaCredentialsFormProps) => {
  return (
    <Controller
      name="githubCredentialsType"
      control={control}
      render={({ field }) => (
        <>
          <div className="flex flex-col gap-4">
            <span className="text-default-500 text-sm">
              Personal Access Token
            </span>
            <WizardRadioCard
              name={field.name}
              value="personal_access_token"
              checked={(field.value || "") === "personal_access_token"}
              isInvalid={isInvalid}
              onChange={(value) => {
                field.onChange(value);
                onChange?.(value);
              }}
            >
              Personal Access Token
            </WizardRadioCard>

            <span className="text-default-500 text-sm">OAuth App</span>
            <WizardRadioCard
              name={field.name}
              value="oauth_app"
              checked={(field.value || "") === "oauth_app"}
              isInvalid={isInvalid}
              onChange={(value) => {
                field.onChange(value);
                onChange?.(value);
              }}
            >
              OAuth App Token
            </WizardRadioCard>

            <span className="text-default-500 text-sm">GitHub App</span>
            <WizardRadioCard
              name={field.name}
              value="github_app"
              checked={(field.value || "") === "github_app"}
              isInvalid={isInvalid}
              onChange={(value) => {
                field.onChange(value);
                onChange?.(value);
              }}
            >
              GitHub App
            </WizardRadioCard>
          </div>
          {errorMessage && (
            <FormMessage className="text-text-error">
              {errorMessage}
            </FormMessage>
          )}
        </>
      )}
    />
  );
};
