"use client";

import { type ChangeEvent, useId } from "react";

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
import type { RegistryCredentialSchema } from "@/lib/registry/provider-credential-schema";

// prettier-ignore
interface RegistryCredentialFieldsProps { readonly errors: Readonly<Record<string, string | undefined>>; readonly onChange: (name: string, value: string) => void; readonly schema: RegistryCredentialSchema; readonly values: Readonly<Record<string, string | undefined>>; }

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
          // prettier-ignore
          onChange: (event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => onChange(field.name, event.target.value),
          required: field.required,
          spellCheck: false,
          value: typeof value === "string" ? value : "",
        };

        return (
          <Field key={field.name}>
            <FieldLabel htmlFor={id}>
              {field.label}
              {field.required && <span aria-hidden="true"> *</span>}
            </FieldLabel>
            {field.kind === "select" ? (
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
                // prettier-ignore
                autoComplete={field.kind === "password" ? "new-password" : "off"}
                type={field.kind === "password" ? "password" : "text"}
                {...textControlProps}
              />
            )}
            {field.description &&
              // prettier-ignore
              <p className="text-text-neutral-secondary text-sm" id={descriptionId}>{field.description}</p>}
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
