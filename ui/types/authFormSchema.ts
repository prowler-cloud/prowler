import { z } from "zod";

import { SPECIAL_CHARACTERS } from "@/lib/utils";

export type AuthSocialProvider = "google" | "github";

export const PASSWORD_REQUIREMENTS = {
  minLength: 12,
  specialChars: SPECIAL_CHARACTERS,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
} as const;

export const passwordRequirementCheckers = {
  minLength: (password: string) =>
    password.length >= PASSWORD_REQUIREMENTS.minLength,
  specialChars: (password: string) =>
    PASSWORD_REQUIREMENTS.specialChars
      .split("")
      .some((char) => password.includes(char)),
  uppercase: (password: string) => /[A-Z]/.test(password),
  lowercase: (password: string) => /[a-z]/.test(password),
  numbers: (password: string) => /[0-9]/.test(password),
};

export const validatePassword = () => {
  const {
    minLength,
    specialChars,
    requireUppercase,
    requireLowercase,
    requireNumbers,
  } = PASSWORD_REQUIREMENTS;

  return z
    .string()
    .min(minLength, {
      message: `Password must contain at least ${minLength} characters.`,
    })
    .refine(passwordRequirementCheckers.specialChars, {
      message: `Password must contain at least one special character from: ${specialChars}`,
    })
    .refine(
      (password) =>
        !requireUppercase || passwordRequirementCheckers.uppercase(password),
      {
        message: "Password must contain at least one uppercase letter.",
      },
    )
    .refine(
      (password) =>
        !requireLowercase || passwordRequirementCheckers.lowercase(password),
      {
        message: "Password must contain at least one lowercase letter.",
      },
    )
    .refine(
      (password) =>
        !requireNumbers || passwordRequirementCheckers.numbers(password),
      {
        message: "Password must contain at least one number.",
      },
    );
};

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
          : z.string().min(1, {
              message: "Please confirm your password.",
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
      password: type === "sign-in" ? z.string() : validatePassword(),
      isSamlMode: z.boolean().optional(),
      // Add a virtual field for global errors
      credentials: z.string().optional(),
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
