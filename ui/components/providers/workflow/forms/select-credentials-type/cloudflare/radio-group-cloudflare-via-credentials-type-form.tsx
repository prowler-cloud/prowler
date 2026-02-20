"use client";

import { RadioGroup } from "@heroui/radio";
import { Control, Controller } from "react-hook-form";

import { CustomRadio } from "@/components/ui/custom";
import { FormMessage } from "@/components/ui/form";

type RadioGroupCloudflareViaCredentialsFormProps = {
  control: Control<any>;
  isInvalid: boolean;
  errorMessage?: string;
  onChange?: (value: string) => void;
};

export const RadioGroupCloudflareViaCredentialsTypeForm = ({
  control,
  isInvalid,
  errorMessage,
  onChange,
}: RadioGroupCloudflareViaCredentialsFormProps) => {
  return (
    <Controller
      name="cloudflareCredentialsType"
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
                description="Connect using a Cloudflare API Token (recommended)"
                value="api_token"
              >
                <div className="flex items-center">
                  <span className="ml-2">API Token</span>
                </div>
              </CustomRadio>
              <CustomRadio
                description="Connect using Global API Key and Email"
                value="api_key"
              >
                <div className="flex items-center">
                  <span className="ml-2">API Key + Email</span>
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
