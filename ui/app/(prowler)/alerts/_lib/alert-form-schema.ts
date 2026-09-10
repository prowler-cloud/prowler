import { z } from "zod";

import {
  ALERT_TRIGGER_KIND_VALUES,
  type AlertCondition,
} from "@/app/(prowler)/alerts/_types";

const alertConditionSchema = z.custom<AlertCondition>(
  (value) => typeof value === "object" && value !== null,
  "Alert condition is required.",
);

export const alertFormSchema = z.object({
  name: z.string().trim().min(1, { error: "Name is required." }).max(120),
  description: z.string().trim().max(2000).default(""),
  frequency: z.enum(ALERT_TRIGGER_KIND_VALUES),
  condition: alertConditionSchema,
  recipientEmails: z
    .array(z.email({ error: "Enter a valid email address." }))
    .default([]),
  slackChannels: z.array(z.string().trim().min(1)).default([]),
  enabled: z.boolean(),
});
