import { z } from "zod";

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

      // Fields for Sign In and Sign Up
      email: z.string().email(),
      password: z.string().min(12, {
        message: "It must contain at least 12 characters.",
      }),
    })
    .refine(
      (data) => type === "sign-in" || data.password === data.confirmPassword,
      {
        message: "The password must match",
        path: ["confirmPassword"],
      },
    );
