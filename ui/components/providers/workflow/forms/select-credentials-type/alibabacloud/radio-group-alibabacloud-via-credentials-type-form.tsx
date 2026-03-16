"use client";

import { Control, Controller, FieldValues, Path } from "react-hook-form";

import { WizardRadioCard } from "@/components/providers/workflow/forms/fields";
import { RadioGroup } from "@/components/shadcn/radio-group/radio-group";
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
            <RadioGroup
              name={field.name}
              value={currentValue}
              onValueChange={(value: string) => {
                field.onChange(value);
                onChange?.(value);
              }}
            >
              <span className="text-default-500 text-sm">Using RAM Role</span>
              <WizardRadioCard value="role" isInvalid={isInvalid}>
                Connect assuming RAM Role
              </WizardRadioCard>
              <span className="text-default-500 text-sm">
                Using Credentials
              </span>
              <WizardRadioCard value="credentials" isInvalid={isInvalid}>
                Connect via Access Keys
              </WizardRadioCard>
            </RadioGroup>
            {errorMessage && (
              <FormMessage className="text-text-error-primary">
                {errorMessage}
              </FormMessage>
            )}
          </>
        );
      }}
    />
  );
};
