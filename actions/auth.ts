"use server";

import { AuthError } from "next-auth";
import { z } from "zod";

import { signIn, signOut } from "@/auth.config";
import { authFormSchema } from "@/types";

const formSchemaSignIn = authFormSchema("sign-in");

const defaultValues: z.infer<typeof formSchemaSignIn> = {
  email: "",
  password: "",
};

export async function authenticate(
  prevState: unknown,
  formData: z.infer<typeof formSchemaSignIn>,
) {
  try {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    await signIn("credentials", {
      ...formData,
      redirect: false,
    });
    return {
      message: "Success",
    };
  } catch (error) {
    if (error instanceof AuthError) {
      switch (error.type) {
        case "CredentialsSignin":
          return {
            message: "Credentials error",
            errors: {
              ...defaultValues,
              credentials: "Incorrect email or password",
            },
          };
        default:
          return {
            message: "Unknown error",
            errors: {
              ...defaultValues,
              unknown: "Unknown error",
            },
          };
      }
    }
  }
}

export async function logOut() {
  await signOut();
}
