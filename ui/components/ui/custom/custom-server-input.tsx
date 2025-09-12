"use client";

import { Input } from "@nextui-org/react";
import React from "react";

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
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
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
  return (
    <div className="flex flex-col">
      <Input
        id={name}
        name={name}
        type={type}
        label={label}
        labelPlacement={labelPlacement}
        placeholder={placeholder}
        variant={variant}
        isRequired={isRequired}
        isInvalid={isInvalid}
        errorMessage={errorMessage}
        value={value}
        onChange={onChange}
        classNames={{
          label: "tracking-tight font-light !text-default-500 text-xs !z-0",
          input: "text-default-500 text-small",
        }}
      />
    </div>
  );
};
