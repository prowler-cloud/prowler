"use client";

import { RadioGroup } from "@heroui/radio";
import React from "react";
import { Control, Controller } from "react-hook-form";

import { CustomRadio } from "@/components/ui/custom";
import { FormMessage } from "@/components/ui/form";

type RadioGroupM365ViaCredentialsFormProps = {
  control: Control<any>;
  isInvalid: boolean;
  errorMessage?: string;
  onChange?: (value: string) => void;
};

export const RadioGroupM365ViaCredentialsTypeForm = ({
  control,
  isInvalid,
  errorMessage,
  onChange,
}: RadioGroupM365ViaCredentialsFormProps) => {
  return (
    <Controller
      name="m365CredentialsType"
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
                Select Authentication Method
              </span>
              <CustomRadio
                description="Connect using Application Client Secret"
                value="app_client_secret"
              >
                <div className="flex items-center">
                  <span className="ml-2">App Client Secret Credentials</span>
                </div>
              </CustomRadio>
              <CustomRadio
                description="Connect using Application Certificate"
                value="app_certificate"
              >
                <div className="flex items-center">
                  <span className="ml-2">App Certificate Credentials</span>
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
