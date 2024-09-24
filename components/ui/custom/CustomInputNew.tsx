import { Input } from "@nextui-org/react";
import { Control, FieldPath, FieldValues } from "react-hook-form";

import { FormControl, FormField, FormMessage } from "@/components/ui/form";

interface CustomInputNewProps<T extends FieldValues> {
  control: Control<T>;
  name: FieldPath<T>;
  label: string;
  type: string;
  placeholder?: string;
  isRequired?: boolean;
}

export const CustomInputNew = <T extends FieldValues>({
  control,
  name,
  label,
  type,
  placeholder,
  isRequired = false,
}: CustomInputNewProps<T>) => {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <>
          <FormControl>
            <Input
              isRequired={isRequired}
              label={label}
              placeholder={placeholder}
              type={type}
              variant="bordered"
              {...field}
            />
          </FormControl>
          <FormMessage className="text-system-error dark:text-system-error" />
        </>
      )}
    />
  );
};
