import type { z } from "zod";

import {
  LIGHTHOUSE_CONTEXT_KIND,
  LIGHTHOUSE_CONTEXT_LIMIT,
  LIGHTHOUSE_CONTEXT_SOURCE,
  LIGHTHOUSE_CONTEXT_TRANSPORT,
  LIGHTHOUSE_PAGE_ID,
} from "@/lib/lighthouse/context/constants";
import type {
  lighthouseAlertContextItemSchema,
  lighthouseAttackPathContextItemSchema,
  lighthouseAttackPathParameterSchema,
  lighthouseAttackPathParametersSchema,
  lighthouseAttackPathTypeCountsSchema,
  lighthouseComplianceContextItemSchema,
  lighthouseComplianceTotalsSchema,
  lighthouseContextEnvelopeSchema,
  lighthouseContextFiltersSchema,
  lighthouseContextItemBaseSchema,
  lighthouseContextItemSchema,
  lighthouseContextSourceSchema,
  lighthouseContextTransportSchema,
  lighthouseFindingContextItemSchema,
  lighthousePageContextItemSchema,
  lighthouseProviderContextItemSchema,
  lighthouseResourceContextItemSchema,
  lighthouseScanContextItemSchema,
} from "@/lib/lighthouse/context/schema";

export {
  LIGHTHOUSE_CONTEXT_KIND,
  LIGHTHOUSE_CONTEXT_LIMIT,
  LIGHTHOUSE_CONTEXT_SOURCE,
  LIGHTHOUSE_CONTEXT_TRANSPORT,
  LIGHTHOUSE_PAGE_ID,
};

export type LighthouseContextSource = z.infer<
  typeof lighthouseContextSourceSchema
>;
export type LighthouseContextTransport = z.infer<
  typeof lighthouseContextTransportSchema
>;
export type LighthousePageId =
  (typeof LIGHTHOUSE_PAGE_ID)[keyof typeof LIGHTHOUSE_PAGE_ID];

export interface LighthousePageSuggestion {
  label: string;
  prompt: string;
}

export type LighthousePageSuggestions = readonly [
  LighthousePageSuggestion,
  LighthousePageSuggestion,
  LighthousePageSuggestion,
  LighthousePageSuggestion,
];

export interface LighthousePageDefinitionInput {
  id: LighthousePageId;
  label: string;
  match: (pathname: string) => boolean;
  allowedSearchParams: readonly string[];
  suggestions: LighthousePageSuggestions;
}

export type LighthouseContextFilters = z.infer<
  typeof lighthouseContextFiltersSchema
>;
export type LighthouseContextItemBase = z.infer<
  typeof lighthouseContextItemBaseSchema
>;
export type LighthousePageContextItem = z.infer<
  typeof lighthousePageContextItemSchema
>;
export type LighthouseFindingContextItem = z.infer<
  typeof lighthouseFindingContextItemSchema
>;
export type LighthouseResourceContextItem = z.infer<
  typeof lighthouseResourceContextItemSchema
>;
export type LighthouseComplianceTotals = z.infer<
  typeof lighthouseComplianceTotalsSchema
>;
export type LighthouseComplianceContextItem = z.infer<
  typeof lighthouseComplianceContextItemSchema
>;
export type LighthouseAttackPathParameter = z.infer<
  typeof lighthouseAttackPathParameterSchema
>;
export type LighthouseAttackPathParameters = z.infer<
  typeof lighthouseAttackPathParametersSchema
>;
export type LighthouseAttackPathTypeCounts = z.infer<
  typeof lighthouseAttackPathTypeCountsSchema
>;
export type LighthouseAttackPathContextItem = z.infer<
  typeof lighthouseAttackPathContextItemSchema
>;
export type LighthouseScanContextItem = z.infer<
  typeof lighthouseScanContextItemSchema
>;
export type LighthouseProviderContextItem = z.infer<
  typeof lighthouseProviderContextItemSchema
>;
export type LighthouseAlertContextItem = z.infer<
  typeof lighthouseAlertContextItemSchema
>;
export type LighthouseContextItem = z.infer<typeof lighthouseContextItemSchema>;
export type LighthouseContextEnvelope = z.infer<
  typeof lighthouseContextEnvelopeSchema
>;
