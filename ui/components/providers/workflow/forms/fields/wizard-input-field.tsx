"use client";

import { Icon } from "@iconify/react";
import { InputHTMLAttributes, useState } from "react";
import { Control, FieldPath, FieldValues } from "react-hook-form";

import { Input } from "@/components/shadcn/input/input";
import { FormControl, FormField, FormMessage } from "@/components/ui/form";
import { cn } from "@/lib/utils";

interface WizardInputFieldProps<T extends FieldValues> {
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
  normalizeValue?: (value: string) => string;
  autoCapitalize?: InputHTMLAttributes<HTMLInputElement>["autoCapitalize"];
  autoCorrect?: InputHTMLAttributes<HTMLInputElement>["autoCorrect"];
  spellCheck?: boolean;
  requiredIndicator?: boolean;
}

export const WizardInputField = <T extends FieldValues>({
  control,
  name,
  type = "text",
  label = name,
  labelPlacement = "inside",
  variant,
  size,
  placeholder,
  confirmPassword = false,
  password = false,
  defaultValue,
  isReadOnly = false,
  isRequired = true,
  isDisabled = false,
  normalizeValue,
  autoCapitalize,
  autoCorrect,
  spellCheck,
  requiredIndicator,
}: WizardInputFieldProps<T>) => {
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);
  const [isConfirmPasswordVisible, setIsConfirmPasswordVisible] =
    useState(false);
  void variant;
  void size;

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

  const isMaskedInput = type === "password" || password || confirmPassword;
  const inputType = isMaskedInput
    ? isPasswordVisible || isConfirmPasswordVisible
      ? "text"
      : "password"
    : type;
  const inputIsRequired = password || confirmPassword ? true : isRequired;
  const showRequiredIndicator = requiredIndicator ?? inputIsRequired;

  const toggleVisibility = () => {
    if (password || type === "password") {
      setIsPasswordVisible((current) => !current);
      return;
    }
    if (confirmPassword) {
      setIsConfirmPasswordVisible((current) => !current);
    }
  };

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
              {inputLabel}
              {showRequiredIndicator && (
                <span className="text-text-error-primary">*</span>
              )}
            </label>
            <FormControl>
              <div className="relative">
                <Input
                  id={name}
                  aria-label={inputLabel}
                  placeholder={inputPlaceholder}
                  type={inputType}
                  required={inputIsRequired}
                  disabled={isDisabled}
                  readOnly={isReadOnly}
                  autoCapitalize={autoCapitalize}
                  autoCorrect={autoCorrect}
                  spellCheck={spellCheck}
                  className={cn(isMaskedInput && "pr-10")}
                  name={field.name}
                  onBlur={field.onBlur}
                  ref={field.ref}
                  onChange={(event) => {
                    if (!normalizeValue) {
                      field.onChange(event);
                      return;
                    }
                    const normalizedValue = normalizeValue(event.target.value);
                    field.onChange(normalizedValue);
                  }}
                  value={value}
                />
                {isMaskedInput && (
                  <button
                    type="button"
                    onClick={toggleVisibility}
                    className="text-default-400 hover:text-default-500 absolute top-1/2 right-3 -translate-y-1/2"
                    aria-label={
                      inputType === "password"
                        ? "Show password"
                        : "Hide password"
                    }
                  >
                    <Icon
                      className="pointer-events-none text-xl"
                      icon={
                        (password && isPasswordVisible) ||
                        (confirmPassword && isConfirmPasswordVisible) ||
                        (type === "password" && isPasswordVisible)
                          ? "solar:eye-closed-linear"
                          : "solar:eye-bold"
                      }
                    />
                  </button>
                )}
              </div>
            </FormControl>
            <FormMessage className="text-text-error-primary max-w-full text-xs" />
          </div>
        );
      }}
    />
  );
};
