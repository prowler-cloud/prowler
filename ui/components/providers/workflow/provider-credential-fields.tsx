"use client";

import { type ChangeEvent, useId } from "react";

import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { Input } from "@/components/shadcn/input/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import type {
  RegistryCredentialSchema,
  RegistryCredentialValue,
} from "@/lib/provider-credentials/provider-credential-schema";

interface RegistryCredentialFieldsProps {
  readonly errors: Readonly<Record<string, string | undefined>>;
  readonly onChange: (name: string, value: RegistryCredentialValue) => void;
  readonly schema: RegistryCredentialSchema;
  readonly values: Readonly<
    Record<string, RegistryCredentialValue | undefined>
  >;
}

export function RegistryCredentialFields({
  errors,
  onChange,
  schema,
  values,
}: RegistryCredentialFieldsProps) {
  const instanceId = useId();

  return (
    <div className="flex flex-col gap-4">
      {schema.fields.map((field, index) => {
        const error = errors[field.name];
        const fieldId = `registry-credential-${instanceId}-${index}`;
        const id = `${fieldId}-control`;
        const descriptionId = field.description
          ? `${fieldId}-description`
          : undefined;
        const errorId = error ? `${fieldId}-error` : undefined;
        const describedBy =
          [descriptionId, errorId].filter(Boolean).join(" ") || undefined;
        const invalid = error ? true : undefined;
        const value = values[field.name];
        const textControlProps = {
          "aria-describedby": describedBy,
          "aria-invalid": invalid,
          id,

          onChange: (
            event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
          ) => onChange(field.name, event.target.value),
          required: field.required,
          placeholder: field.placeholder,
          spellCheck: false,
          value:
            typeof value === "string" || typeof value === "number" ? value : "",
        };

        return (
          <Field key={field.name}>
            {field.kind === "checkbox" ? (
              <div className="flex items-center gap-2">
                <Checkbox
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  aria-required={field.required}
                  checked={value === true}
                  id={id}
                  onCheckedChange={(checked) =>
                    onChange(field.name, checked === true)
                  }
                />
                <FieldLabel htmlFor={id}>
                  {field.label}
                  {field.required && <span aria-hidden="true"> *</span>}
                </FieldLabel>
              </div>
            ) : (
              <FieldLabel htmlFor={id}>
                {field.label}
                {field.required && <span aria-hidden="true"> *</span>}
              </FieldLabel>
            )}
            {field.kind === "checkbox" ? null : field.kind === "select" ? (
              <Select
                onValueChange={(nextValue) => onChange(field.name, nextValue)}
                value={typeof value === "string" ? value : ""}
              >
                <SelectTrigger
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  aria-label={field.label}
                  aria-required={field.required}
                  id={id}
                >
                  <SelectValue placeholder="Select an option" />
                </SelectTrigger>
                <SelectContent>
                  {field.options?.map((option) => (
                    <SelectItem key={option} value={option}>
                      {option}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : field.kind === "textarea" ? (
              <Textarea autoComplete="off" {...textControlProps} />
            ) : (
              <Input
                autoComplete={
                  field.kind === "password" ? "new-password" : "off"
                }
                type={
                  field.kind === "integer"
                    ? "number"
                    : field.kind === "password"
                      ? "password"
                      : "text"
                }
                min={field.minimum}
                max={field.maximum}
                step={field.kind === "integer" ? 1 : undefined}
                {...textControlProps}
              />
            )}
            {field.description && (
              <p
                className="text-text-neutral-secondary text-sm"
                id={descriptionId}
              >
                {field.description}
              </p>
            )}
            {error && (
              <FieldError id={errorId} role="alert">
                {error}
              </FieldError>
            )}
          </Field>
        );
      })}
    </div>
  );
}
