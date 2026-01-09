"use client";

import { RadioGroup } from "@heroui/radio";
import { Control, Controller, FieldValues, Path } from "react-hook-form";

import { CustomRadio } from "@/components/ui/custom";
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
              <span className="text-default-500 text-sm">Using RAM Role</span>
              <CustomRadio description="Connect assuming RAM Role" value="role">
                <div className="flex items-center">
                  <span className="ml-2">Connect assuming RAM Role</span>
                </div>
              </CustomRadio>
              <span className="text-default-500 text-sm">
                Using Credentials
              </span>
              <CustomRadio
                description="Connect via Access Keys"
                value="credentials"
              >
                <div className="flex items-center">
                  <span className="ml-2">Connect via Access Keys</span>
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
