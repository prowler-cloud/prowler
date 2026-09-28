import { z } from "zod";

import {
  PROVIDER_SCHEMA_STATUS,
  type ProviderSchemasSuccessResult,
} from "@/types/provider-schema";

const providerTypeSchema = z.string().trim().toLowerCase().min(1).max(50);
const providerSchemasDocumentSchema = z.strictObject({
  data: z.strictObject({
    type: z.literal("provider-schemas"),
    id: z.string().min(1).max(50),
    attributes: z.strictObject({
      secret_types: z.record(z.string(), z.record(z.string(), z.unknown())),
    }),
  }),
});

export function normalizeProviderType(value: unknown): string | null {
  const parsed = providerTypeSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

export function adaptProviderSchemas(
  payload: unknown,
  normalizedProviderType: string,
): ProviderSchemasSuccessResult | null {
  const parsed = providerSchemasDocumentSchema.safeParse(payload);
  if (!parsed.success || parsed.data.data.id !== normalizedProviderType) {
    return null;
  }

  return {
    status: PROVIDER_SCHEMA_STATUS.SUCCESS,
    providerType: parsed.data.data.id,
    secretTypes: parsed.data.data.attributes.secret_types,
  };
}
