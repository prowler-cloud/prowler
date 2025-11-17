"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
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
  const getValidationSchema = () => {
    const schemaObject: Record<string, z.ZodTypeAny> = {};

    if (selectedQuery) {
      const query = availableQueries.find((q) => q.id === selectedQuery);

      if (query) {
        query.attributes.parameters.forEach((param) => {
          let fieldSchema: z.ZodTypeAny = z.string();

          if (param.data_type === "number") {
            fieldSchema = z.coerce.number();
          } else if (param.data_type === "boolean") {
            fieldSchema = z.boolean().default(false);
          }

          if (!param.required) {
            fieldSchema = fieldSchema.optional();
          }

          schemaObject[param.name] = fieldSchema;
        });
      }
    }

    return z.object(schemaObject);
  };

  const form = useForm({
    resolver: zodResolver(getValidationSchema()),
    mode: "onChange",
  });

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
