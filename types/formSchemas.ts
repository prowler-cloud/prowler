import { z } from "zod";

export const addProviderFormSchema = z.object({
  providerType: z.string(),
  providerAlias: z.string(),
  providerId: z.string(),
});

export const editProviderFormSchema = (currentAlias: string) =>
  z.object({
    alias: z
      .string()
      .refine((val) => val === "" || val.length >= 3, {
        message: "The alias must be empty or have at least 3 characters.",
      })
      .refine((val) => val !== currentAlias, {
        message: "The new alias must be different from the current one.",
      })
      .optional(),
    providerId: z.string(),
  });
