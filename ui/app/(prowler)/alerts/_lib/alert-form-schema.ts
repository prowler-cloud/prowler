import { z } from "zod";

import {
  ALERT_DELTA_VALUES,
  ALERT_PROVIDER_TYPE_VALUES,
  ALERT_SEVERITY_VALUES,
  ALERT_TRIGGER_KIND_VALUES,
} from "@/app/(prowler)/alerts/_types";

import {
  ALERT_FILTER_FIELDS,
  ALERT_FILTER_OPERATORS,
  ALERT_NOTIFICATION_METHODS,
} from "../_types/alert-form";

const alertFilterItemSchema = z.object({
  kind: z.literal("filter"),
  field: z.enum(Object.values(ALERT_FILTER_FIELDS)),
  values: z.array(z.string().trim()).default([]),
});

type AlertFormFilterNodeSchema =
  | z.infer<typeof alertFilterItemSchema>
  | {
      kind: "group";
      operator: (typeof ALERT_FILTER_OPERATORS)[keyof typeof ALERT_FILTER_OPERATORS];
      children: AlertFormFilterNodeSchema[];
    };

const alertFilterNodeSchema: z.ZodType<AlertFormFilterNodeSchema> = z.lazy(() =>
  z.union([
    alertFilterItemSchema,
    z.object({
      kind: z.literal("group"),
      operator: z.enum(Object.values(ALERT_FILTER_OPERATORS)),
      children: z.array(alertFilterNodeSchema),
    }),
  ]),
);

export const alertFormSchema = z.object({
  name: z.string().trim().min(1, { error: "Name is required." }).max(120),
  description: z.string().trim().max(2000).default(""),
  method: z.literal(ALERT_NOTIFICATION_METHODS.EMAIL),
  frequency: z.enum(ALERT_TRIGGER_KIND_VALUES),
  filterGroup: z.object({
    operator: z.enum(Object.values(ALERT_FILTER_OPERATORS)),
    children: z.array(alertFilterNodeSchema).min(1),
  }),
  severities: z.array(z.enum(ALERT_SEVERITY_VALUES)).default([]),
  deltas: z.array(z.enum(ALERT_DELTA_VALUES)).default([]),
  providerTypes: z.array(z.enum(ALERT_PROVIDER_TYPE_VALUES)).default([]),
  providerIds: z.array(z.string().trim().min(1)).default([]),
  checkIds: z.array(z.string().trim().min(1)).default([]),
  categories: z.array(z.string().trim().min(1)).default([]),
  regions: z.array(z.string().trim().min(1)).default([]),
  services: z.array(z.string().trim().min(1)).default([]),
  resourceGroups: z.array(z.string().trim().min(1)).default([]),
  findingGroupIds: z.array(z.string().trim().min(1)).default([]),
  resourceTypes: z.array(z.string().trim().min(1)).default([]),
  recipientEmails: z
    .array(z.email({ error: "Enter a valid email address." }))
    .default([]),
  enabled: z.boolean(),
});

export type AlertFormSchemaValues = z.infer<typeof alertFormSchema>;
