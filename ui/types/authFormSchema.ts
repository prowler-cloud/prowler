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

const baseAuthSchema = z.object({
  email: z
    .email({ message: "Please enter a valid email address." })
    .trim()
    .toLowerCase(),
  password: z.string(),
  isSamlMode: z.boolean().optional(),
});

export const signInSchema = baseAuthSchema
  .extend({
    password: z.string(),
  })
  .refine(
    (data) => {
      // If SAML mode, password is not required
      if (data.isSamlMode) return true;
      // Otherwise, password must be filled
      return data.password.length > 0;
    },
    {
      message: "Password is required.",
      path: ["password"],
    },
  );

export const signUpSchema = baseAuthSchema
  .extend({
    name: z
      .string()
      .min(3, {
        message: "The name must be at least 3 characters.",
      })
      .max(20),
    password: validatePassword(),
    confirmPassword: z.string().min(1, {
      message: "Please confirm your password.",
    }),
    company: z.string().optional(),
    invitationToken: z.string().optional(),
    termsAndConditions:
      process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true"
        ? z.boolean().refine((value) => value === true, {
            message: "You must accept the terms and conditions.",
          })
        : z.boolean().optional(),
  })
  .refine(
    (data) => {
      if (data.isSamlMode) return true;
      return data.password === data.confirmPassword;
    },
    {
      message: "The password must match",
      path: ["confirmPassword"],
    },
  );

export const authFormSchema = (type: string) =>
  type === "sign-in" ? signInSchema : signUpSchema;

export type SignInFormData = z.infer<typeof signInSchema>;
export type SignUpFormData = z.infer<typeof signUpSchema>;
