"use client";

import type { ChangeEvent } from "react";

import { Field, FieldError, FieldLabel, Input } from "@/components/shadcn";
import { cn } from "@/lib/utils";

interface CustomServerInputProps {
  name: string;
  label?: string;
  labelPlacement?: "inside" | "outside";
  variant?: "flat" | "bordered" | "underlined" | "faded";
  type?: string;
  placeholder?: string;
  isRequired?: boolean;
  isInvalid?: boolean;
  errorMessage?: string;
  value?: string;
  onChange?: (e: ChangeEvent<HTMLInputElement>) => void;
}

/**
 * Custom input component that is used to display a server input without useForm hook.
 */
export const CustomServerInput = ({
  name,
  type = "text",
  label,
  labelPlacement = "outside",
  placeholder,
  variant = "bordered",
  isRequired = false,
  isInvalid = false,
  errorMessage,
  value,
  onChange,
}: CustomServerInputProps) => {
  void variant;

  return (
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
      <Input
        id={name}
        name={name}
        type={type}
        placeholder={placeholder}
        required={isRequired}
        aria-invalid={isInvalid || undefined}
        className={cn(
          "text-text-neutral-secondary",
          isInvalid &&
            "border-border-error focus:border-border-error focus:ring-border-error",
        )}
        value={value}
        onChange={onChange}
      />
      {isInvalid && errorMessage && <FieldError>{errorMessage}</FieldError>}
    </Field>
  );
};
