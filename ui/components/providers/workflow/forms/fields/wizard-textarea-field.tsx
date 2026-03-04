"use client";

import { Control, FieldPath, FieldValues } from "react-hook-form";

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
}: WizardTextareaFieldProps<T>) => {
  void variant;
  void size;
  void fullWidth;
  void disableAutosize;

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
                "text-sm font-medium",
                labelPlacement === "outside" ? "" : "sr-only",
              )}
            >
              {label}
            </label>
            <FormControl>
              <textarea
                id={name}
                aria-label={label}
                placeholder={placeholder}
                required={isRequired}
                rows={maxRows ? Math.min(minRows, maxRows) : minRows}
                className={cn(
                  "border-border-input-primary bg-bg-input-primary placeholder:text-text-neutral-tertiary focus-visible:border-border-input-primary-press focus-visible:ring-border-input-primary-press min-h-16 w-full rounded-lg border px-4 py-3 text-sm outline-none focus-visible:ring-1 focus-visible:ring-inset",
                  description ? "mb-1" : "",
                )}
                {...field}
                value={value}
              />
            </FormControl>
            {description && (
              <p className="text-text-neutral-tertiary max-w-full text-xs">
                {description}
              </p>
            )}
            <FormMessage className="text-text-error max-w-full text-xs" />
          </div>
        );
      }}
    />
  );
};
