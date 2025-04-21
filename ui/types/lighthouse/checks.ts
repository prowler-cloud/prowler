import { z } from "zod";

export const checkSchema = z.object({
  provider_type: z.enum(["aws", "gcp", "azure", "kubernetes", "microsoft365"]),
});
