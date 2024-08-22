"use client";

import { Icon } from "@iconify/react";
import { Input } from "@nextui-org/react";
import React, { useState } from "react";
import { Control, FieldPath } from "react-hook-form";
import { z } from "zod";

import { FormControl, FormField, FormMessage } from "@/components/ui/form";
import { authFormSchema } from "@/types";

type CustomInputProps =
  | {
      control: Control<z.infer<typeof authFormSchema>>;
      name: FieldPath<z.infer<typeof authFormSchema>>;
      password?: false;
      label: string;
      type: "text" | "email";
      placeholder: string;
      isRequired?: boolean;
    }
  | {
      control: Control<z.infer<typeof authFormSchema>>;
      password: true;
      name?: never;
      label?: never;
      type?: never;
      placeholder?: never;
      isRequired?: never;
    };

export const CustomInput = ({
  control,
  name,
  type,
  label,
  placeholder,
  password = false,
  isRequired = true,
}: CustomInputProps) => {
  const [isVisible, setIsVisible] = useState(false);

  const toggleVisibility = () => setIsVisible(!isVisible);

  const inputProps = password
    ? {
        name: "password",
        label: "Password",
        type: isVisible ? "text" : "password",
        placeholder: "Enter your password",
        isRequired: true,
      }
    : { name, label, type, placeholder, isRequired };

  return (
    <FormField
      control={control}
      name={inputProps.name}
      render={({ field }) => (
        <>
          <FormControl>
            <Input
              isRequired={inputProps.isRequired}
              label={inputProps.label}
              placeholder={inputProps.placeholder}
              type={inputProps.type}
              variant="bordered"
              {...field}
              endContent={
                password && (
                  <button type="button" onClick={toggleVisibility}>
                    <Icon
                      className="pointer-events-none text-2xl text-default-400"
                      icon={
                        isVisible ? "solar:eye-closed-linear" : "solar:eye-bold"
                      }
                    />
                  </button>
                )
              }
            />
          </FormControl>
          <FormMessage />
        </>
      )}
    />
  );
};
