import { z } from "zod";

import {
  LIGHTHOUSE_CONTEXT_KIND,
  LIGHTHOUSE_CONTEXT_SOURCE,
  LIGHTHOUSE_CONTEXT_TRANSPORT,
} from "@/types/lighthouse-context";

const boundedStringSchema = z.string().max(256);
const boundedCountSchema = z.number().int().nonnegative();
const filtersSchema = z
  .record(boundedStringSchema, z.array(boundedStringSchema))
  .refine(
    (filters) =>
      Object.values(filters).reduce(
        (total, values) => total + values.length,
        0,
      ) <= 20,
    { error: "Filters may contain at most 20 values." },
  );

const baseContextItemSchema = z.object({
  id: boundedStringSchema,
  source: z.enum(LIGHTHOUSE_CONTEXT_SOURCE),
  scopeKey: boundedStringSchema,
  label: boundedStringSchema,
});

const pageContextItemSchema = baseContextItemSchema.extend({
  kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.PAGE),
  path: boundedStringSchema,
  filters: filtersSchema.optional(),
});

const findingContextItemSchema = baseContextItemSchema.extend({
  kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.FINDING),
  findingId: boundedStringSchema,
  checkId: boundedStringSchema.optional(),
  severity: boundedStringSchema.optional(),
  status: boundedStringSchema.optional(),
  providerUid: boundedStringSchema.optional(),
  resourceUid: boundedStringSchema.optional(),
  region: boundedStringSchema.optional(),
  total: boundedCountSchema.optional(),
});

const resourceContextItemSchema = baseContextItemSchema.extend({
  kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.RESOURCE),
  resourceId: boundedStringSchema,
  resourceUid: boundedStringSchema.optional(),
  providerUid: boundedStringSchema.optional(),
  service: boundedStringSchema.optional(),
  region: boundedStringSchema.optional(),
  resourceType: boundedStringSchema.optional(),
  failedFindingsCount: boundedCountSchema.optional(),
  total: boundedCountSchema.optional(),
});

const complianceContextItemSchema = baseContextItemSchema.extend({
  kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.COMPLIANCE),
  framework: boundedStringSchema,
  version: boundedStringSchema.optional(),
  scanId: boundedStringSchema.optional(),
  providerUid: boundedStringSchema.optional(),
  mode: boundedStringSchema.optional(),
  section: boundedStringSchema.optional(),
  region: boundedStringSchema.optional(),
  score: z.number().min(0).max(100).optional(),
  totals: z
    .object({
      passed: boundedCountSchema.optional(),
      failed: boundedCountSchema.optional(),
      total: boundedCountSchema.optional(),
    })
    .optional(),
});

const attackPathContextItemSchema = baseContextItemSchema.extend({
  kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.ATTACK_PATH),
  scanId: boundedStringSchema.optional(),
  queryId: boundedStringSchema.optional(),
  parameters: z
    .record(
      boundedStringSchema,
      z.union([boundedStringSchema, z.number(), z.boolean()]),
    )
    .optional(),
  nodeCount: boundedCountSchema.optional(),
  edgeCount: boundedCountSchema.optional(),
  selectedNodeId: boundedStringSchema.optional(),
  selectedNodeType: boundedStringSchema.optional(),
});

const scanContextItemSchema = baseContextItemSchema.extend({
  kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.SCAN),
  scanId: boundedStringSchema.optional(),
  state: boundedStringSchema.optional(),
  providerUid: boundedStringSchema.optional(),
  total: boundedCountSchema.optional(),
});

const providerContextItemSchema = baseContextItemSchema.extend({
  kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.PROVIDER),
  providerId: boundedStringSchema.optional(),
  providerUid: boundedStringSchema.optional(),
  providerType: boundedStringSchema.optional(),
  total: boundedCountSchema.optional(),
});

export const lighthouseContextItemSchema = z.discriminatedUnion("kind", [
  pageContextItemSchema,
  findingContextItemSchema,
  resourceContextItemSchema,
  complianceContextItemSchema,
  attackPathContextItemSchema,
  scanContextItemSchema,
  providerContextItemSchema,
]);

export const lighthouseContextEnvelopeSchema = z.object({
  schemaVersion: z.literal(1),
  transport: z.literal(LIGHTHOUSE_CONTEXT_TRANSPORT.INLINE),
  items: z.array(lighthouseContextItemSchema).max(8),
});
