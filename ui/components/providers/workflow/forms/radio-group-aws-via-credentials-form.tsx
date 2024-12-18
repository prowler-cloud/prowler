"use client";

import { RadioGroup } from "@nextui-org/react";
import React from "react";
import { Control, Controller } from "react-hook-form";

import { CustomRadio } from "@/components/ui/custom";
import { FormMessage } from "@/components/ui/form";

type RadioGroupAWSViaCredentialsFormProps = {
  control: Control<any>;
  isInvalid: boolean;
  errorMessage?: string;
  onChange?: (value: string) => void;
};

export const RadioGroupAWSViaCredentialsForm = ({
  control,
  isInvalid,
  errorMessage,
  onChange,
}: RadioGroupAWSViaCredentialsFormProps) => {
  return (
    <Controller
      name="awsCredentialsType"
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
              <span className="text-sm text-default-500">Using IAM Role</span>
              <CustomRadio description="Connect assuming IAM Role" value="role">
                <div className="flex items-center">
                  <span className="ml-2">Connect assuming IAM Role</span>
                </div>
              </CustomRadio>
              <span className="text-sm text-default-500">
                Using Credentials
              </span>
              <CustomRadio
                description="Connect via Credentials"
                value="credentials"
              >
                <div className="flex items-center">
                  <span className="ml-2">Connect via Credentials</span>
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
