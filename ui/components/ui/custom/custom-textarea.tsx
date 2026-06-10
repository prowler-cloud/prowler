"use client";

import type { ReactNode } from "react";
import { Control, FieldPath, FieldValues } from "react-hook-form";

import { Field, FieldError, FieldLabel, Textarea } from "@/components/shadcn";
import { FormControl, FormField } from "@/components/ui/form";
import { cn } from "@/lib/utils";

const SIZE_MAP = { sm: "sm", md: "default", lg: "lg" } as const;

interface CustomTextareaProps<T extends FieldValues> {
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
  description?: ReactNode;
}

export const CustomTextarea = <T extends FieldValues>({
  control,
  name,
  label = name,
  labelPlacement = "inside",
  placeholder,
  variant = "flat",
  size = "md",
  defaultValue,
  isRequired = false,
  minRows = 3,
  maxRows = 8,
  fullWidth = true,
  disableAutosize = false,
  description,
}: CustomTextareaProps<T>) => {
  void variant;
  void defaultValue;
  void maxRows;
  void fullWidth;
  void disableAutosize;

  return (
    <FormField
      control={control}
      name={name}
      render={({ field, fieldState }) => (
        <Field>
          {label && (
            <FieldLabel
              htmlFor={name}
              className={cn(
                labelPlacement === "inside" && "font-light tracking-tight",
              )}
            >
              {label}
              {isRequired && <span className="text-text-error-primary">*</span>}
            </FieldLabel>
          )}
          <FormControl>
            <Textarea
              id={name}
              textareaSize={SIZE_MAP[size]}
              placeholder={placeholder}
              required={isRequired}
              rows={minRows}
              aria-invalid={!!fieldState.error}
              className={cn(
                fieldState.error &&
                  "border-border-error focus:border-border-error focus:ring-border-error",
              )}
              {...field}
              value={field.value ?? ""}
            />
          </FormControl>
          {description && (
            <p className="text-text-neutral-tertiary text-xs">{description}</p>
          )}
          {fieldState.error?.message && (
            <FieldError>{fieldState.error.message}</FieldError>
          )}
        </Field>
      )}
    />
  );
};
