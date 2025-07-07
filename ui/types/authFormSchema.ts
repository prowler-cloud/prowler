import { z } from "zod";

export type AuthSocialProvider = "google" | "github";

export const authFormSchema = (type: string) =>
  z
    .object({
      // Sign Up
      company:
        type === "sign-in" ? z.string().optional() : z.string().optional(),
      name:
        type === "sign-in"
          ? z.string().optional()
          : z
              .string()
              .min(3, {
                message: "The name must be at least 3 characters.",
              })
              .max(20),
      confirmPassword:
        type === "sign-in"
          ? z.string().optional()
          : z.string().min(12, {
              message: "It must contain at least 12 characters.",
            }),
      invitationToken:
        type === "sign-in" ? z.string().optional() : z.string().optional(),

      termsAndConditions:
        type === "sign-in" || process.env.NEXT_PUBLIC_IS_CLOUD_ENV !== "true"
          ? z.boolean().optional()
          : z.boolean().refine((value) => value === true, {
              message: "You must accept the terms and conditions.",
            }),

      // Fields for Sign In and Sign Up
      email: z.string().email(),
      password:
        type === "sign-in"
          ? z.string()
          : z.string().min(12, {
              message: "It must contain at least 12 characters.",
            }),
      isSamlMode: z.boolean().optional(),
    })
    .refine(
      (data) => {
        if (data.isSamlMode) return true;
        return type === "sign-in" || data.password === data.confirmPassword;
      },
      {
        message: "The password must match",
        path: ["confirmPassword"],
      },
    );
