"use server";

import { AuthError } from "next-auth";

import { signIn, signOut } from "@/auth.config";
import { apiBaseUrl } from "@/lib";
import { fetchCurrentUser } from "@/lib/auth/current-user";
import { addAuthEvent } from "@/lib/sentry-breadcrumbs";
import type { UtmParams } from "@/lib/utm";
import type { SignInFormData, SignUpFormData } from "@/types";

export async function authenticate(
  prevState: unknown,
  formData: SignInFormData,
) {
  try {
    addAuthEvent("login", { email: formData.email });
    await signIn("credentials", {
      ...formData,
      redirect: false,
    });
    return {
      message: "Success",
    };
  } catch (error) {
    if (error instanceof AuthError) {
      addAuthEvent("error", { type: error.type });
      switch (error.type) {
        case "CredentialsSignin":
          return {
            message: "Credentials error",
            errors: {
              credentials: "Invalid email or password",
            },
          };
        case "CallbackRouteError":
          return {
            message: error.cause?.err?.message,
          };
        default:
          return {
            message: "Unknown error",
            errors: {
              unknown: "Unknown error",
            },
          };
      }
    }
  }
}

export const createNewUser = async (
  formData: SignUpFormData,
  attribution: UtmParams = {},
) => {
  const url = new URL(`${apiBaseUrl}/users`);

  if (formData.invitationToken) {
    url.searchParams.append("invitation_token", formData.invitationToken);
  }

  for (const [key, value] of Object.entries(attribution)) {
    url.searchParams.append(key, value);
  }

  const bodyData = {
    data: {
      type: "users",
      attributes: {
        name: formData.name,
        email: formData.email,
        password: formData.password,
        ...(formData.company && { company_name: formData.company }),
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
      return { ...parsedResponse, status: response.status };
    }

    return parsedResponse;
  } catch (_error) {
    return {
      errors: [
        {
          source: { pointer: "" },
          detail: "Network error or server is unreachable",
        },
      ],
    };
  }
};

export const getToken = async (formData: SignInFormData) => {
  const url = new URL(`${apiBaseUrl}/tokens`);

  const bodyData = {
    data: {
      type: "tokens",
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
  } catch (_error) {
    throw new Error("Error in trying to get token");
  }
};

export const getUserByMe = async (accessToken: string) => {
  const currentUser = await fetchCurrentUser(accessToken);

  return {
    name: currentUser.name,
    email: currentUser.email,
    company: currentUser.company,
    dateJoined: currentUser.dateJoined,
    permissions: currentUser.permissions,
  };
};

export async function logOut() {
  await signOut({ redirectTo: "/sign-in" });
}
