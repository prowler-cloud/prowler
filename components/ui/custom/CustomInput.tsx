"use client";

import { Icon } from "@iconify/react";
import { Input } from "@nextui-org/react";
import React, { useState } from "react";
import { Control, FieldPath } from "react-hook-form";
import { z } from "zod";

import { FormControl, FormField, FormMessage } from "@/components/ui/form";
import { authFormSchema } from "@/types";

const formSchema = authFormSchema("sign-up");

type CustomInputProps =
  | {
      control: Control<z.infer<typeof formSchema>>;
      name: FieldPath<z.infer<typeof formSchema>>;
      label: string;
      type: "text" | "email";
      placeholder: string;
      isRequired?: boolean;
      password?: false;
    }
  | {
      control: Control<z.infer<typeof formSchema>>;
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

  const inputName = password ? "password" : name!;
  const inputLabel = password ? "Password" : label;
  const inputType = password ? (isVisible ? "text" : "password") : type;
  const inputPlaceholder = password ? "Enter your password" : placeholder;
  const inputIsRequired = password ? true : isRequired;

  return (
    <FormField
      control={control}
      name={inputName as FieldPath<z.infer<typeof formSchema>>}
      render={({ field }) => (
        <>
          <FormControl>
            <Input
              isRequired={inputIsRequired}
              label={inputLabel}
              placeholder={inputPlaceholder}
              type={inputType}
              variant="bordered"
              {...field}
              endContent={
                password ? (
                  <button type="button" onClick={toggleVisibility}>
                    <Icon
                      className="pointer-events-none text-2xl text-default-400"
                      icon={
                        isVisible ? "solar:eye-closed-linear" : "solar:eye-bold"
                      }
                    />
                  </button>
                ) : null
              }
            />
          </FormControl>
          <FormMessage />
        </>
      )}
    />
  );
};
