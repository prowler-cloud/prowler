"use client";

import { useFormContext } from "react-hook-form";

import { Input, Textarea } from "@/components/shadcn";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { cn } from "@/lib/utils";
import {
  type AttackPathQuery,
  QUERY_PARAMETER_INPUT_TYPES,
} from "@/types/attack-paths";

import { QueryCodeEditor } from "./query-code-editor";

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
  const { control } = useFormContext();

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
          <FormField
            key={param.name}
            name={param.name}
            control={control}
            render={({ field, fieldState }) => {
              if (param.data_type === "boolean") {
                return (
                  <FormItem className="flex flex-col gap-2">
                    <label className="flex cursor-pointer items-center gap-3">
                      <FormControl>
                        <input
                          type="checkbox"
                          checked={
                            field.value === true || field.value === "true"
                          }
                          onChange={(e) => field.onChange(e.target.checked)}
                          aria-label={param.label}
                          className="border-border-neutral-secondary bg-bg-neutral-primary text-text-primary focus:ring-primary dark:border-border-neutral-secondary dark:bg-bg-neutral-primary dark:text-text-primary h-4 w-4 rounded border focus:ring-2"
                        />
                      </FormControl>
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
                    <FormMessage className="text-xs" />
                  </FormItem>
                );
              }

              const placeholder =
                param.description ||
                param.placeholder ||
                `Enter ${param.label.toLowerCase()}`;

              const isTextarea =
                param.input_type === QUERY_PARAMETER_INPUT_TYPES.TEXTAREA;
              const isCodeEditor =
                param.input_type === QUERY_PARAMETER_INPUT_TYPES.CODE_EDITOR;

              return (
                <FormItem
                  className={cn(
                    "flex flex-col gap-1.5",
                    (isTextarea || isCodeEditor) && "md:col-span-2",
                  )}
                >
                  {!isCodeEditor && (
                    <FormLabel className="text-text-neutral-tertiary text-xs font-medium">
                      {param.label}
                      {param.required && (
                        <span className="text-text-error-primary">*</span>
                      )}
                    </FormLabel>
                  )}
                  {isCodeEditor ? (
                    <FormControl>
                      <QueryCodeEditor
                        ariaLabel={param.label}
                        language={param.editor_language}
                        value={String(field.value ?? "")}
                        placeholder={placeholder}
                        invalid={fieldState.invalid}
                        requirementBadge={param.requirement_badge}
                        onChange={field.onChange}
                        onBlur={field.onBlur}
                      />
                    </FormControl>
                  ) : (
                    <FormControl>
                      {isTextarea ? (
                        <Textarea
                          {...field}
                          textareaSize="lg"
                          placeholder={placeholder}
                          value={field.value ?? ""}
                          className="min-h-40 font-mono text-xs"
                        />
                      ) : (
                        <Input
                          {...field}
                          type={
                            param.data_type === "number" ? "number" : "text"
                          }
                          placeholder={placeholder}
                          value={field.value ?? ""}
                        />
                      )}
                    </FormControl>
                  )}
                  <FormMessage className="text-xs" />
                </FormItem>
              );
            }}
          />
        ))}
      </div>
    </div>
  );
};
