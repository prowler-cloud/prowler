"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  CUSTOM_ATTACK_PATH_QUERY_READ_ONLY_ERROR_MESSAGE,
  customAttackPathQuerySchema,
} from "@/lib/attack-paths/custom-query";
import {
  ATTACK_PATH_QUERY_IDS,
  type AttackPathQuery,
  QUERY_PARAMETER_INPUT_TYPES,
} from "@/types/attack-paths";

const getValidationSchema = (query?: AttackPathQuery) => {
  const schemaObject: Record<string, z.ZodTypeAny> = {};

  query?.attributes.parameters.forEach((param) => {
    const isCustomQueryParameter =
      query.id === ATTACK_PATH_QUERY_IDS.CUSTOM &&
      param.name === "query" &&
      param.input_type === QUERY_PARAMETER_INPUT_TYPES.CODE_EDITOR;

    let fieldSchema: z.ZodTypeAny = isCustomQueryParameter
      ? customAttackPathQuerySchema
      : z.string().min(1, `${param.label} is required`);

    if (param.data_type === "number") {
      fieldSchema = z.coerce.number().refine((val) => val >= 0, {
        message: `${param.label} must be a non-negative number`,
      });
    } else if (param.data_type === "boolean") {
      fieldSchema = z.boolean().default(false);
    }

    schemaObject[param.name] = fieldSchema;
  });

  return z.object(schemaObject);
};

const getDefaultValues = (query?: AttackPathQuery) => {
  const defaults: Record<string, unknown> = {};

  query?.attributes.parameters.forEach((param) => {
    defaults[param.name] = param.data_type === "boolean" ? false : "";
  });

  return defaults;
};

/**
 * Custom hook for managing query builder form state
 * Handles query selection, parameter validation, and form submission
 */
export const useQueryBuilder = (availableQueries: AttackPathQuery[]) => {
  const [selectedQuery, setSelectedQuery] = useState<string | null>(null);

  const getQueryById = (queryId: string | null) =>
    availableQueries.find((query) => query.id === queryId);
  const selectedQueryData = getQueryById(selectedQuery);

  const form = useForm({
    resolver: zodResolver(getValidationSchema(selectedQueryData)),
    mode: "onChange",
    defaultValues: getDefaultValues(selectedQueryData),
    shouldUnregister: true,
  });

  // Update form when selectedQuery changes
  useEffect(() => {
    form.reset(getDefaultValues(selectedQueryData), {
      keepDirtyValues: false,
    });
  }, [form, selectedQueryData]);

  const handleQueryChange = (queryId: string) => {
    setSelectedQuery(queryId);
  };

  const getQueryParameters = () => {
    if (!selectedQueryData?.attributes.parameters.length) {
      return undefined;
    }

    const values = form.getValues() as Record<
      string,
      string | number | boolean
    >;

    return selectedQueryData.attributes.parameters.reduce<
      Record<string, string | number | boolean>
    >((parameters, parameter) => {
      const value = values[parameter.name];
      if (value !== undefined) {
        parameters[parameter.name] = value;
      }
      return parameters;
    }, {});
  };

  const isFormValid = () => {
    return form.formState.isValid;
  };

  const isExecutionBlocked =
    selectedQueryData?.id === ATTACK_PATH_QUERY_IDS.CUSTOM &&
    form.formState.errors.query?.message ===
      CUSTOM_ATTACK_PATH_QUERY_READ_ONLY_ERROR_MESSAGE;

  return {
    selectedQuery,
    selectedQueryData,
    availableQueries,
    form,
    handleQueryChange,
    getQueryParameters,
    isFormValid,
    isExecutionBlocked,
  };
};
