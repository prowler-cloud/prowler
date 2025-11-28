"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import type { AttackPathQuery } from "@/types/attack-paths";

/**
 * Custom hook for managing query builder form state
 * Handles query selection, parameter validation, and form submission
 */
export const useQueryBuilder = (availableQueries: AttackPathQuery[]) => {
  const [selectedQuery, setSelectedQuery] = useState<string | null>(null);

  // Generate dynamic Zod schema based on selected query parameters
  const getValidationSchema = (queryId: string | null) => {
    const schemaObject: Record<string, z.ZodTypeAny> = {};

    if (queryId) {
      const query = availableQueries.find((q) => q.id === queryId);

      if (query) {
        query.attributes.parameters.forEach((param) => {
          let fieldSchema: z.ZodTypeAny = z
            .string()
            .min(1, `${param.label} is required`);

          if (param.data_type === "number") {
            fieldSchema = z.coerce.number().refine((val) => val >= 0, {
              message: `${param.label} must be a non-negative number`,
            });
          } else if (param.data_type === "boolean") {
            fieldSchema = z.boolean().default(false);
          }

          schemaObject[param.name] = fieldSchema;
        });
      }
    }

    return z.object(schemaObject);
  };

  const getDefaultValues = (queryId: string | null) => {
    const defaults: Record<string, unknown> = {};

    const query = availableQueries.find((q) => q.id === queryId);
    if (query) {
      query.attributes.parameters.forEach((param) => {
        defaults[param.name] = param.data_type === "boolean" ? false : "";
      });
    }

    return defaults;
  };

  const form = useForm({
    resolver: zodResolver(getValidationSchema(selectedQuery)),
    mode: "onChange",
    defaultValues: getDefaultValues(selectedQuery),
  });

  // Update form when selectedQuery changes
  useEffect(() => {
    form.reset(getDefaultValues(selectedQuery), {
      keepDirtyValues: false,
    });
  }, [selectedQuery]); // eslint-disable-line react-hooks/exhaustive-deps

  const selectedQueryData = availableQueries.find(
    (q) => q.id === selectedQuery,
  );

  const handleQueryChange = (queryId: string) => {
    setSelectedQuery(queryId);
    form.reset();
  };

  const getQueryParameters = () => {
    return form.getValues();
  };

  const isFormValid = () => {
    return form.formState.isValid;
  };

  return {
    selectedQuery,
    selectedQueryData,
    availableQueries,
    form,
    handleQueryChange,
    getQueryParameters,
    isFormValid,
  };
};
