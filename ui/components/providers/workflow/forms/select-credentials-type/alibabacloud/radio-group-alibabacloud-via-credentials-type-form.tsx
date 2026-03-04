"use client";

import { Control, Controller, FieldValues, Path } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
import { FormMessage } from "@/components/ui/form";

type RadioGroupAlibabaCloudViaCredentialsFormProps<T extends FieldValues> = {
  control: Control<T>;
  isInvalid: boolean;
  errorMessage?: string;
  onChange?: (value: string) => void;
};

export const RadioGroupAlibabaCloudViaCredentialsTypeForm = <
  T extends FieldValues,
>({
  control,
  isInvalid,
  errorMessage,
  onChange,
}: RadioGroupAlibabaCloudViaCredentialsFormProps<T>) => {
  return (
    <Controller
      name={"alibabacloudCredentialsType" as Path<T>}
      control={control}
      render={({ field }) => {
        const currentValue = String(field.value ?? "");

        return (
          <>
            <div className="flex flex-col gap-4">
              <span className="text-default-500 text-sm">Using RAM Role</span>
              <WizardRadioCard
                name={field.name}
                value="role"
                checked={currentValue === "role"}
                isInvalid={isInvalid}
                onChange={(value) => {
                  field.onChange(value);
                  onChange?.(value);
                }}
              >
                Connect assuming RAM Role
              </WizardRadioCard>
              <span className="text-default-500 text-sm">
                Using Credentials
              </span>
              <WizardRadioCard
                name={field.name}
                value="credentials"
                checked={currentValue === "credentials"}
                isInvalid={isInvalid}
                onChange={(value) => {
                  field.onChange(value);
                  onChange?.(value);
                }}
              >
                Connect via Access Keys
              </WizardRadioCard>
            </div>
            {errorMessage && (
              <FormMessage className="text-text-error">
                {errorMessage}
              </FormMessage>
            )}
          </>
        );
      }}
    />
  );
};
