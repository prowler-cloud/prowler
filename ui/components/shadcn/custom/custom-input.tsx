"use client";

import { Icon } from "@iconify/react";
import { useState } from "react";
import { Control, FieldPath, FieldValues } from "react-hook-form";

import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { FormControl, FormField } from "@/components/shadcn/form";
import { Input } from "@/components/shadcn/input/input";
import { cn } from "@/lib/utils";

const SIZE_MAP = { sm: "sm", md: "default", lg: "lg" } as const;

interface CustomInputProps<T extends FieldValues> {
  control: Control<T>;
  name: FieldPath<T>;
  label?: string;
  labelPlacement?: "inside" | "outside";
  variant?: "flat" | "bordered" | "underlined" | "faded";
  size?: "sm" | "md" | "lg";
  type?: string;
  placeholder?: string;
  password?: boolean;
  confirmPassword?: boolean;
  defaultValue?: string;
  isReadOnly?: boolean;
  isRequired?: boolean;
  isDisabled?: boolean;
}

export const CustomInput = <T extends FieldValues>({
  control,
  name,
  type = "text",
  label = name,
  labelPlacement = "inside",
  placeholder,
  variant = "bordered",
  size = "md",
  confirmPassword = false,
  password = false,
  defaultValue,
  isReadOnly = false,
  isRequired = true,
  isDisabled = false,
}: CustomInputProps<T>) => {
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);
  const [isConfirmPasswordVisible, setIsConfirmPasswordVisible] =
    useState(false);
  void variant;
  void defaultValue;

  const inputLabel = confirmPassword
    ? "Confirm Password"
    : password
      ? "Password"
      : label;

  const inputPlaceholder = confirmPassword
    ? "Confirm Password"
    : password
      ? "Password"
      : placeholder;

  const isMaskedInput = password || confirmPassword;
  const inputType = isMaskedInput
    ? isPasswordVisible || isConfirmPasswordVisible
      ? "text"
      : "password"
    : type;
  const inputIsRequired = isMaskedInput ? true : isRequired;

  const toggleVisibility = () => {
    if (password) {
      setIsPasswordVisible(!isPasswordVisible);
    } else if (confirmPassword) {
      setIsConfirmPasswordVisible(!isConfirmPasswordVisible);
    }
  };

  return (
    <FormField
      control={control}
      name={name}
      render={({ field, fieldState }) => (
        <Field>
          {inputLabel && (
            <FieldLabel
              htmlFor={name}
              className={cn(
                labelPlacement === "inside" && "font-light tracking-tight",
              )}
            >
              {inputLabel}
              {inputIsRequired && (
                <span className="text-text-error-primary">*</span>
              )}
            </FieldLabel>
          )}
          <div className="relative">
            <FormControl>
              <Input
                id={name}
                type={inputType}
                inputSize={SIZE_MAP[size]}
                placeholder={inputPlaceholder}
                required={inputIsRequired}
                disabled={isDisabled}
                readOnly={isReadOnly}
                aria-invalid={!!fieldState.error}
                className={cn(
                  "text-text-neutral-secondary",
                  isMaskedInput && "pr-10",
                  fieldState.error &&
                    "border-border-error focus:border-border-error focus:ring-border-error",
                )}
                {...field}
                value={field.value ?? ""}
              />
            </FormControl>
            {isMaskedInput && (
              <button
                type="button"
                onClick={toggleVisibility}
                className="absolute top-1/2 right-3 -translate-y-1/2"
                aria-label={
                  inputType === "password" ? "Show password" : "Hide password"
                }
              >
                <Icon
                  className="text-text-neutral-tertiary pointer-events-none text-2xl"
                  icon={
                    (password && isPasswordVisible) ||
                    (confirmPassword && isConfirmPasswordVisible)
                      ? "solar:eye-closed-linear"
                      : "solar:eye-bold"
                  }
                />
              </button>
            )}
          </div>
          {fieldState.error?.message && (
            <FieldError>{fieldState.error.message}</FieldError>
          )}
        </Field>
      )}
    />
  );
};
