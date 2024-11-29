"use client";

import { Textarea } from "@nextui-org/input";
import React from "react";
import { Control, FieldPath, FieldValues } from "react-hook-form";

import { FormControl, FormField, FormMessage } from "@/components/ui/form";

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
  isInvalid?: boolean;
  minRows?: number;
  maxRows?: number;
  fullWidth?: boolean;
  disableAutosize?: boolean;
  description?: React.ReactNode;
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
  isInvalid = false,
  minRows = 3,
  maxRows = 8,
  fullWidth = true,
  disableAutosize = false,
  description,
}: CustomTextareaProps<T>) => {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <>
          <FormControl>
            <Textarea
              id={name}
              label={label}
              labelPlacement={labelPlacement}
              placeholder={placeholder}
              variant={variant}
              size={size}
              isInvalid={isInvalid}
              isRequired={isRequired}
              defaultValue={defaultValue}
              minRows={minRows}
              maxRows={maxRows}
              fullWidth={fullWidth}
              disableAutosize={disableAutosize}
              description={description}
              {...field}
            />
          </FormControl>
          <FormMessage className="text-system-error dark:text-system-error" />
        </>
      )}
    />
  );
};
