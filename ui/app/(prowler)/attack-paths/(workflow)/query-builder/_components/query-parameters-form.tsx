"use client";

import { Checkbox } from "@heroui/checkbox";
import { Input } from "@heroui/input";
import { Controller, useFormContext } from "react-hook-form";

import type { AttackPathQuery } from "@/types/attack-paths";

interface QueryParametersFormProps {
  selectedQuery: AttackPathQuery | null | undefined;
}

/**
 * Dynamic form component for query parameters
 * Renders form fields based on selected query's parameters
 */
export const QueryParametersForm = ({
  selectedQuery,
}: QueryParametersFormProps) => {
  const {
    control,
    formState: { errors },
  } = useFormContext();

  if (!selectedQuery || !selectedQuery.attributes.parameters.length) {
    return (
      <div className="rounded-lg bg-blue-50 p-4 dark:bg-blue-950/20">
        <p className="text-sm text-blue-700 dark:text-blue-300">
          This query requires no parameters. Click &quot;Execute Query&quot; to
          proceed.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <h3 className="dark:text-prowler-theme-pale/90 text-sm font-semibold">
        Query Parameters
      </h3>

      {selectedQuery.attributes.parameters.map((param) => (
        <Controller
          key={param.name}
          name={param.name}
          control={control}
          render={({ field }) => {
            if (param.data_type === "boolean") {
              return (
                <div className="flex flex-col gap-2">
                  <label className="flex cursor-pointer items-center gap-3">
                    <Checkbox
                      {...field}
                      checked={field.value === true || field.value === "true"}
                      size="lg"
                    />
                    <div className="flex flex-col gap-1">
                      <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                        {param.label}
                      </span>
                      {param.description && (
                        <span className="text-xs text-gray-600 dark:text-gray-400">
                          {param.description}
                        </span>
                      )}
                    </div>
                  </label>
                </div>
              );
            }

            return (
              <Input
                {...field}
                label={param.label}
                placeholder={
                  param.placeholder || `Enter ${param.label.toLowerCase()}`
                }
                description={param.description}
                type={param.data_type === "number" ? "number" : "text"}
                isRequired={param.required}
                isInvalid={!!errors[param.name]}
                errorMessage={
                  typeof errors[param.name]?.message === "string"
                    ? (errors[param.name]?.message as string)
                    : undefined
                }
                size="lg"
              />
            );
          }}
        />
      ))}
    </div>
  );
};
