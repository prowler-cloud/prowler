import { z } from "zod";

export const authFormSchema = (type: string) =>
  z.object({
    // Sign Up
    companyName: type === "sign-in" ? z.string().optional() : z.string().min(3),
    firstName:
      type === "sign-in"
        ? z.string().optional()
        : z
            .string()
            .min(3, {
              message: "The name must be at least 3 characters.",
            })
            .max(20),
    termsAndConditions:
      type === "sign-in"
        ? z.enum(["true"]).optional()
        : z.enum(["true"], {
            errorMap: () => ({
              message: "You must accept the terms and conditions.",
            }),
          }),
    // both
    email: z.string().email(),
    password: z.string().min(6),
  });
