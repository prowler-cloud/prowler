import { z } from "zod";

export const checkSchema = z.object({
  providerType: z.enum(["aws", "gcp", "azure", "kubernetes", "m365"]),
  service: z.array(z.string()).optional(),
  severity: z
    .array(z.enum(["informational", "low", "medium", "high", "critical"]))
    .optional(),
  compliances: z.array(z.string()).optional(),
});

export const checkDetailsSchema = z.object({
  id: z.string(),
});
