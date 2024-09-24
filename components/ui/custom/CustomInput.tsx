"use client";

import { Icon } from "@iconify/react";
import { Input } from "@nextui-org/react";
import React, { useState } from "react";
import { Control, FieldPath, FieldValues } from "react-hook-form";

import { FormControl, FormField, FormMessage } from "@/components/ui/form";

interface CustomInputProps<T extends FieldValues> {
  control: Control<T>;
  name: FieldPath<T>;
  label?: string;
  type?: string;
  placeholder?: string;
  isRequired?: boolean;
  password?: boolean;
}

export const CustomInput = <T extends FieldValues>({
  control,
  name,
  type = "text",
  label = name,
  placeholder,
  password = false,
  isRequired = true,
}: CustomInputProps<T>) => {
  const [isVisible, setIsVisible] = useState(false);

  const toggleVisibility = () => setIsVisible(!isVisible);

  const inputLabel = password ? "Password" : label;
  const inputType = password ? (isVisible ? "text" : "password") : type;
  const inputPlaceholder = password ? "Enter your password" : placeholder;
  const inputIsRequired = password ? true : isRequired;

  const endContent = password && (
    <button type="button" onClick={toggleVisibility}>
      <Icon
        className="pointer-events-none text-2xl text-default-400"
        icon={isVisible ? "solar:eye-closed-linear" : "solar:eye-bold"}
      />
    </button>
  );

  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <>
          <FormControl>
            <Input
              isRequired={inputIsRequired}
              label={inputLabel}
              placeholder={inputPlaceholder}
              type={inputType}
              variant="bordered"
              endContent={endContent}
              {...field}
            />
          </FormControl>
          <FormMessage className="text-system-error dark:text-system-error" />
        </>
      )}
    />
  );
};
