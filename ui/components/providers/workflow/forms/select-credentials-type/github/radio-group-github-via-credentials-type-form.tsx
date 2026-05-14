"use client";

import { Control, Controller } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
import { RadioGroup } from "@/components/shadcn/radio-group/radio-group";
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
          <RadioGroup
            name={field.name}
            value={field.value || ""}
            onValueChange={(value: string) => {
              field.onChange(value);
              onChange?.(value);
            }}
          >
            <span className="text-default-500 text-sm">
              Personal Access Token
            </span>
            <WizardRadioCard
              value="personal_access_token"
              isInvalid={isInvalid}
            >
              Personal Access Token
            </WizardRadioCard>

            <span className="text-default-500 text-sm">OAuth App</span>
            <WizardRadioCard value="oauth_app" isInvalid={isInvalid}>
              OAuth App Token
            </WizardRadioCard>

            <span className="text-default-500 text-sm">GitHub App</span>
            <WizardRadioCard value="github_app" isInvalid={isInvalid}>
              GitHub App
            </WizardRadioCard>
          </RadioGroup>
          {errorMessage && (
            <FormMessage className="text-text-error-primary">
              {errorMessage}
            </FormMessage>
          )}
        </>
      )}
    />
  );
};
