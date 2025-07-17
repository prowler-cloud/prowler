"use client";

import { RadioGroup } from "@nextui-org/react";
import React from "react";
import { Control, Controller } from "react-hook-form";

import { CustomRadio } from "@/components/ui/custom";
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
            className="flex flex-wrap"
            isInvalid={isInvalid}
            {...field}
            value={field.value || ""}
            onValueChange={(value) => {
              field.onChange(value);
              if (onChange) {
                onChange(value);
              }
            }}
          >
            <div className="flex flex-col gap-4">
              <span className="text-sm text-default-500">
                Authentication Methods
              </span>
              <CustomRadio
                description="Use a personal access token for individual user authentication"
                value="personal_access_token"
              >
                <div className="flex items-center">
                  <span className="ml-2">Personal Access Token</span>
                </div>
              </CustomRadio>
              <CustomRadio
                description="Use an OAuth app token for application-level authentication"
                value="oauth_app_token"
              >
                <div className="flex items-center">
                  <span className="ml-2">OAuth App Token</span>
                </div>
              </CustomRadio>
              <CustomRadio
                description="Use GitHub App credentials (requires App ID and Private Key)"
                value="github_app"
              >
                <div className="flex items-center">
                  <span className="ml-2">GitHub App</span>
                </div>
              </CustomRadio>
            </div>
          </RadioGroup>
          {errorMessage && (
            <FormMessage className="text-system-error dark:text-system-error">
              {errorMessage}
            </FormMessage>
          )}
        </>
      )}
    />
  );
};
