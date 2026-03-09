"use client";

import { Control, FieldPath, FieldValues } from "react-hook-form";

import { Textarea } from "@/components/shadcn/textarea/textarea";
import { FormControl, FormField, FormMessage } from "@/components/ui/form";
import { cn } from "@/lib/utils";

interface WizardTextareaFieldProps<T extends FieldValues> {
  control: Control<T>;
  name: FieldPath<T>;
  label?: string;
  labelPlacement?: "inside" | "outside" | "outside-left";
  variant?: "flat" | "bordered" | "underlined" | "faded";
  size?: "sm" | "md" | "lg";
  placeholder?: string;
  defaultValue?: string;
  isRequired?: boolean;
  minRows?: number;
  maxRows?: number;
  fullWidth?: boolean;
  disableAutosize?: boolean;
  description?: React.ReactNode;
  requiredIndicator?: boolean;
}

export const WizardTextareaField = <T extends FieldValues>({
  control,
  name,
  label = name,
  labelPlacement = "inside",
  variant,
  size,
  placeholder,
  defaultValue,
  isRequired = false,
  minRows = 3,
  maxRows,
  fullWidth = true,
  disableAutosize = false,
  description,
  requiredIndicator,
}: WizardTextareaFieldProps<T>) => {
  void variant;
  void size;
  void fullWidth;
  void disableAutosize;
  const showRequiredIndicator = requiredIndicator ?? isRequired;

  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => {
        const value = field.value ?? defaultValue ?? "";

        return (
          <div className="flex flex-col gap-1.5">
            <label
              htmlFor={name}
              className={cn(
                "text-text-neutral-tertiary text-xs",
                labelPlacement === "outside"
                  ? "font-medium"
                  : "font-light tracking-tight",
              )}
            >
              {label}
              {showRequiredIndicator && (
                <span className="text-text-error-primary">*</span>
              )}
            </label>
            <FormControl>
              <Textarea
                id={name}
                aria-label={label}
                placeholder={placeholder}
                required={isRequired}
                rows={maxRows ? Math.min(minRows, maxRows) : minRows}
                className={cn(description && "mb-1")}
                {...field}
                value={value}
              />
            </FormControl>
            {description && (
              <p className="text-text-neutral-tertiary max-w-full text-xs">
                {description}
              </p>
            )}
            <FormMessage className="text-text-error-primary max-w-full text-xs" />
          </div>
        );
      }}
    />
  );
};
