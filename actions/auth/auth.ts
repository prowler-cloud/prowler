"use server";

import { AuthError } from "next-auth";
import { z } from "zod";

import { signIn, signOut } from "@/auth.config";
import { authFormSchema } from "@/types";

const formSchemaSignIn = authFormSchema("sign-in");
const formSchemaSignUp = authFormSchema("sign-up");

const defaultValues: z.infer<typeof formSchemaSignIn> = {
  email: "",
  password: "",
};

export async function authenticate(
  prevState: unknown,
  formData: z.infer<typeof formSchemaSignIn>,
) {
  try {
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

export const createNewUser = async (
  formData: z.infer<typeof formSchemaSignUp>,
) => {
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/users`);

  const bodyData = {
    data: {
      type: "User",
      attributes: {
        name: formData.name,
        email: formData.email,
        password: formData.password,
      },
    },
  };

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
      },
      body: JSON.stringify(bodyData),
    });

    const parsedResponse = await response.json();

    if (!response.ok) {
      return parsedResponse;
    }

    return parsedResponse;
  } catch (error) {
    return { errors: [{ detail: "Network error or server is unreachable" }] };
  }
};

export const getToken = async (formData: z.infer<typeof formSchemaSignIn>) => {
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/tokens`);

  const bodyData = {
    data: {
      type: "Token",
      attributes: {
        email: formData.email,
        password: formData.password,
      },
    },
  };

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
      },
      body: JSON.stringify(bodyData),
    });

    if (!response.ok) return null;

    const parsedResponse = await response.json();

    const accessToken = parsedResponse.data.attributes.access;
    const refreshToken = parsedResponse.data.attributes.refresh;
    return {
      accessToken,
      refreshToken,
    };
  } catch (error) {
    throw new Error("Error in trying to get token");
  }
};

export const getUserByMe = async (accessToken: string) => {
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/users/me`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) throw new Error("Error in trying to get user by me");

    const parsedResponse = await response.json();

    const name = parsedResponse.data.attributes.name;
    const email = parsedResponse.data.attributes.email;
    const company = parsedResponse.data.attributes.company_name;
    const dateJoined = parsedResponse.data.attributes.date_joined;
    return {
      name,
      email,
      company,
      dateJoined,
    };
  } catch (error) {
    throw new Error("Error in trying to get user by me");
  }
};

export async function logOut() {
  await signOut();
}
