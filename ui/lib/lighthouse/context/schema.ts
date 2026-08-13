import { z } from "zod";

import { ATTACK_PATH_QUERY_KIND } from "@/types/attack-paths";

import {
  LIGHTHOUSE_COMPLIANCE_CONTEXT_MODE,
  LIGHTHOUSE_CONTEXT_KIND,
  LIGHTHOUSE_CONTEXT_LIMIT,
  LIGHTHOUSE_CONTEXT_SOURCE,
  LIGHTHOUSE_CONTEXT_TRANSPORT,
} from "./constants";

const boundedStringSchema = z
  .string()
  .max(LIGHTHOUSE_CONTEXT_LIMIT.STRING_LENGTH);
const boundedCountSchema = z.number().int().nonnegative();

export const lighthouseContextSourceSchema = z.enum(LIGHTHOUSE_CONTEXT_SOURCE);
export const lighthouseContextTransportSchema = z.literal(
  LIGHTHOUSE_CONTEXT_TRANSPORT.INLINE,
);
export const lighthouseContextFiltersSchema = z
  .record(boundedStringSchema, z.array(boundedStringSchema))
  .refine(
    (filters) =>
      Object.values(filters).reduce(
        (total, values) => total + values.length,
        0,
      ) <= LIGHTHOUSE_CONTEXT_LIMIT.FILTER_VALUES,
    {
      error: `Filters may contain at most ${LIGHTHOUSE_CONTEXT_LIMIT.FILTER_VALUES} values.`,
    },
  );
export const lighthouseAttackPathTypeCountsSchema = z
  .record(boundedStringSchema, boundedCountSchema)
  .refine(
    (counts) =>
      Object.keys(counts).length <=
      LIGHTHOUSE_CONTEXT_LIMIT.ATTACK_PATH_TYPE_COUNTS,
    {
      error: `Attack Path type counts may contain at most ${LIGHTHOUSE_CONTEXT_LIMIT.ATTACK_PATH_TYPE_COUNTS} entries.`,
    },
  );

export const lighthouseFindingSeverityCountsSchema = z
  .record(boundedStringSchema, boundedCountSchema)
  .refine(
    (counts) =>
      Object.keys(counts).length <= LIGHTHOUSE_CONTEXT_LIMIT.SEVERITY_COUNTS,
    {
      error: `Severity counts may contain at most ${LIGHTHOUSE_CONTEXT_LIMIT.SEVERITY_COUNTS} entries.`,
    },
  );

export const lighthouseContextItemBaseSchema = z.object({
  id: boundedStringSchema,
  source: lighthouseContextSourceSchema,
  scopeKey: boundedStringSchema,
  label: boundedStringSchema,
});

export const lighthousePageContextItemSchema =
  lighthouseContextItemBaseSchema.extend({
    kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.PAGE),
    path: boundedStringSchema,
    filters: lighthouseContextFiltersSchema.optional(),
  });

export const lighthouseFindingContextItemSchema =
  lighthouseContextItemBaseSchema.extend({
    kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.FINDING),
    findingId: boundedStringSchema,
    checkId: boundedStringSchema.optional(),
    severity: boundedStringSchema.optional(),
    status: boundedStringSchema.optional(),
    providerUid: boundedStringSchema.optional(),
    resourceUid: boundedStringSchema.optional(),
    region: boundedStringSchema.optional(),
    total: boundedCountSchema.optional(),
    passed: boundedCountSchema.optional(),
    failed: boundedCountSchema.optional(),
    newPassed: boundedCountSchema.optional(),
    newFailed: boundedCountSchema.optional(),
    severityCounts: lighthouseFindingSeverityCountsSchema.optional(),
  });

export const lighthouseResourceContextItemSchema =
  lighthouseContextItemBaseSchema.extend({
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

export const lighthouseComplianceTotalsSchema = z.object({
  passed: boundedCountSchema.optional(),
  failed: boundedCountSchema.optional(),
  total: boundedCountSchema.optional(),
});

export const lighthouseComplianceContextItemSchema =
  lighthouseContextItemBaseSchema.extend({
    kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.COMPLIANCE),
    framework: boundedStringSchema,
    version: boundedStringSchema.optional(),
    scanId: boundedStringSchema.optional(),
    providerUid: boundedStringSchema.optional(),
    mode: z.enum(LIGHTHOUSE_COMPLIANCE_CONTEXT_MODE).optional(),
    section: boundedStringSchema.optional(),
    region: boundedStringSchema.optional(),
    score: z.number().min(0).max(100).optional(),
    scoreDelta: z.number().min(-100).max(100).optional(),
    criticalRequirementsCount: boundedCountSchema.optional(),
    worstSection: boundedStringSchema.optional(),
    worstSectionScore: z.number().min(0).max(100).optional(),
    totals: lighthouseComplianceTotalsSchema.optional(),
  });

export const lighthouseAttackPathParameterSchema = z.union([
  boundedStringSchema,
  z.number(),
  z.boolean(),
]);
export const lighthouseAttackPathParametersSchema = z.record(
  boundedStringSchema,
  lighthouseAttackPathParameterSchema,
);

export const lighthouseAttackPathContextItemSchema =
  lighthouseContextItemBaseSchema.extend({
    kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.ATTACK_PATH),
    scanId: boundedStringSchema.optional(),
    queryId: boundedStringSchema.optional(),
    queryKind: z.enum(ATTACK_PATH_QUERY_KIND).optional(),
    canReplayQuery: z.boolean().optional(),
    parameters: lighthouseAttackPathParametersSchema.optional(),
    redactedParameters: z
      .array(boundedStringSchema)
      .max(LIGHTHOUSE_CONTEXT_LIMIT.ATTACK_PATH_REDACTED_PARAMETERS)
      .optional(),
    nodeCount: boundedCountSchema.optional(),
    edgeCount: boundedCountSchema.optional(),
    connectedComponentCount: boundedCountSchema.optional(),
    nodeTypeCounts: lighthouseAttackPathTypeCountsSchema.optional(),
    relationshipTypeCounts: lighthouseAttackPathTypeCountsSchema.optional(),
    selectedNodeId: boundedStringSchema.optional(),
    selectedNodeType: boundedStringSchema.optional(),
  });

export const lighthouseScanContextItemSchema =
  lighthouseContextItemBaseSchema.extend({
    kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.SCAN),
    scanId: boundedStringSchema.optional(),
    state: boundedStringSchema.optional(),
    providerUid: boundedStringSchema.optional(),
    total: boundedCountSchema.optional(),
  });

export const lighthouseProviderContextItemSchema =
  lighthouseContextItemBaseSchema.extend({
    kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.PROVIDER),
    providerId: boundedStringSchema.optional(),
    providerUid: boundedStringSchema.optional(),
    providerType: boundedStringSchema.optional(),
    total: boundedCountSchema.optional(),
  });

export const lighthouseAlertContextItemSchema =
  lighthouseContextItemBaseSchema.extend({
    kind: z.literal(LIGHTHOUSE_CONTEXT_KIND.ALERT),
    alertId: boundedStringSchema.optional(),
    trigger: boundedStringSchema.optional(),
    enabled: z.boolean().optional(),
    total: boundedCountSchema.optional(),
    enabledCount: boundedCountSchema.optional(),
  });

export const lighthouseContextItemSchema = z.discriminatedUnion("kind", [
  lighthousePageContextItemSchema,
  lighthouseFindingContextItemSchema,
  lighthouseResourceContextItemSchema,
  lighthouseComplianceContextItemSchema,
  lighthouseAttackPathContextItemSchema,
  lighthouseScanContextItemSchema,
  lighthouseProviderContextItemSchema,
  lighthouseAlertContextItemSchema,
]);

export const lighthouseContextEnvelopeSchema = z.object({
  schemaVersion: z.literal(1),
  transport: lighthouseContextTransportSchema,
  items: z
    .array(lighthouseContextItemSchema)
    .max(LIGHTHOUSE_CONTEXT_LIMIT.ITEMS),
});
