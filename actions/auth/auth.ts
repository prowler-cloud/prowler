"use server";

import { jwtDecode, JwtPayload } from "jwt-decode";
import { AuthError } from "next-auth";
import { z } from "zod";

import { signIn, signOut } from "@/auth.config";
import { parseStringify } from "@/lib";
import { authFormSchema } from "@/types";

interface CustomJwtPayload extends JwtPayload {
  user_id: string;
}

const formSchemaSignIn = authFormSchema("sign-in");
// const formSchemaSignUp = authFormSchema("sign-up");

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

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    const parsedData = parseStringify(data);

    const accessToken = parsedData.data.attributes.access;
    const refreshToken = parsedData.data.attributes.refresh;

    const decodedToken = jwtDecode<CustomJwtPayload>(accessToken);
    const userId = decodedToken.user_id;

    // Verify if the response contains the expected data
    if (data && data.data && data.data.attributes) {
      return {
        email: formData.email,
        accessToken,
        refreshToken,
        userId,
        // Add here other user fields we need in the session
      };
    }
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error en trying to get token:", error);
  }
};

export async function logOut() {
  await signOut();
}
