"use client";

import { RadioGroup } from "@heroui/radio";
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
              <span className="text-default-500 text-sm">
                Personal Access Token
              </span>
              <CustomRadio
                description="Use a personal access token for authentication"
                value="personal_access_token"
              >
                <div className="flex items-center">
                  <span className="ml-2">Personal Access Token</span>
                </div>
              </CustomRadio>

              <span className="text-default-500 text-sm">OAuth App</span>
              <CustomRadio
                description="Use OAuth App token for authentication"
                value="oauth_app"
              >
                <div className="flex items-center">
                  <span className="ml-2">OAuth App Token</span>
                </div>
              </CustomRadio>

              <span className="text-default-500 text-sm">GitHub App</span>
              <CustomRadio
                description="Use GitHub App ID and private key for authentication"
                value="github_app"
              >
                <div className="flex items-center">
                  <span className="ml-2">GitHub App</span>
                </div>
              </CustomRadio>
            </div>
          </RadioGroup>
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
