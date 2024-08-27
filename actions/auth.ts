"use server";

import { AuthError } from "next-auth";

import { signIn, signOut } from "@/auth.config";
// import { authFormSchema } from "@/types";

// const formSchema = authFormSchema("sign-in");

const defaultValues = {
  email: "",
  password: "",
};

// Fix TS types.
export async function authenticate(prevState: any, formData: any) {
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
