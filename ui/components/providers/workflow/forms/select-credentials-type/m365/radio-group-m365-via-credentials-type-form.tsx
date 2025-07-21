import { RadioGroup } from "@nextui-org/react";
import { Control, Controller } from "react-hook-form";

import { CustomRadio } from "@/components/ui/custom";
import { FormMessage } from "@/components/ui/form";

interface RadioGroupM365ViaCredentialsFormProps {
  control: Control<any>;
  isInvalid?: boolean;
  errorMessage?: string;
  onChange?: (value: string) => void;
}

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
              <span className="text-sm text-default-500">
                Application Authentication
              </span>
              <CustomRadio
                description="Connect using Service Principal credentials only"
                value="credentials"
              >
                <div className="flex items-center">
                  <span className="ml-2">Service Principal</span>
                </div>
              </CustomRadio>
              <span className="text-sm text-default-500">
                Application + User Authentication
              </span>
              <CustomRadio
                description="Connect using Service Principal + User credentials"
                value="service-principal-user"
              >
                <div className="flex items-center">
                  <span className="ml-2">
                    Service Principal + User Credentials
                  </span>
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
