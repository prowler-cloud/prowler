import { z } from "zod";

export const checkSchema = z.object({
  providerType: z.enum(["aws", "gcp", "azure", "kubernetes", "m365"]),
});
