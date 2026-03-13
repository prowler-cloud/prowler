"use client";

import { Controller, useFormContext } from "react-hook-form";

import { Input } from "@/components/shadcn";
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
    return null;
  }

  return (
    <div className="flex flex-col gap-4">
      <h3 className="dark:text-prowler-theme-pale/90 text-sm font-semibold">
        Query Parameters
      </h3>

      <div
        data-testid="query-parameters-grid"
        className="grid grid-cols-1 gap-4 md:grid-cols-2"
      >
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
                      <input
                        type="checkbox"
                        id={param.name}
                        checked={field.value === true || field.value === "true"}
                        onChange={(e) => field.onChange(e.target.checked)}
                        aria-label={param.label}
                        className="border-border-neutral-secondary bg-bg-neutral-primary text-text-primary focus:ring-primary dark:border-border-neutral-secondary dark:bg-bg-neutral-primary dark:text-text-primary h-4 w-4 rounded border focus:ring-2"
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

              const errorMessage = (() => {
                const error = errors[param.name];
                if (error && typeof error.message === "string") {
                  return error.message;
                }
                return undefined;
              })();

              return (
                <div className="flex flex-col gap-1.5">
                  <label
                    htmlFor={param.name}
                    className="text-text-neutral-tertiary text-xs font-medium"
                  >
                    {param.label}
                    {param.required && (
                      <span className="text-text-error-primary">*</span>
                    )}
                  </label>
                  <Input
                    {...field}
                    id={param.name}
                    type={param.data_type === "number" ? "number" : "text"}
                    placeholder={
                      param.description ||
                      param.placeholder ||
                      `Enter ${param.label.toLowerCase()}`
                    }
                    value={field.value ?? ""}
                  />
                  {errorMessage && (
                    <span className="text-xs text-red-500">{errorMessage}</span>
                  )}
                </div>
              );
            }}
          />
        ))}
      </div>
    </div>
  );
};
