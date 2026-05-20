"use server";

import { AuthError } from "next-auth";

import { signIn, signOut } from "@/auth.config";
import { apiBaseUrl } from "@/lib";
import { addAuthEvent } from "@/lib/sentry-breadcrumbs";
import type { SignInFormData, SignUpFormData } from "@/types";

export async function authenticate(
  prevState: unknown,
  formData: SignInFormData,
) {
  try {
    addAuthEvent("login", { email: formData.email });
    const result = await signIn("credentials", {
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
        case "CallbackRouteError": {
          const errMsg = error.cause?.err?.message;
          if (errMsg && errMsg.startsWith("mfa_required:")) {
            const mfaData = JSON.parse(errMsg.replace("mfa_required:", ""));
            return {
              message: "mfa_required",
              mfaData,
            };
          }
          return {
            message: errMsg,
          };
        }
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

export const createNewUser = async (formData: SignUpFormData) => {
  const url = new URL(`${apiBaseUrl}/users`);

  if (formData.invitationToken) {
    url.searchParams.append("invitation_token", formData.invitationToken);
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
      return parsedResponse;
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

    const parsedResponse = await response.json();

    // Handle MFA required response
    if (parsedResponse.data?.attributes?.mfa_required) {
      return {
        mfaRequired: true,
        email: parsedResponse.data.attributes.email,
        tenantId: parsedResponse.data.attributes.tenant_id,
      };
    }

    if (!response.ok) return null;

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
  const url = new URL(`${apiBaseUrl}/users/me?include=roles`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const parsedResponse = await response.json();
    if (!response.ok) {
      // Handle different HTTP error codes
      switch (response.status) {
        case 401:
          throw new Error("Invalid or expired token");
        case 403:
          throw new Error(parsedResponse.errors?.[0]?.detail);
        case 404:
          throw new Error("User not found");
        default:
          throw new Error(
            parsedResponse.errors?.[0]?.detail || "Unknown error",
          );
      }
    }

    const userRole = parsedResponse.included?.find(
      (item: any) => item.type === "roles",
    );

    const permissions = {
      manage_users: userRole.attributes.manage_users || false,
      manage_account: userRole.attributes.manage_account || false,
      manage_providers: userRole.attributes.manage_providers || false,
      manage_scans: userRole.attributes.manage_scans || false,
      manage_integrations: userRole.attributes.manage_integrations || false,
      manage_billing: userRole.attributes.manage_billing || false,
      manage_alerts: userRole.attributes.manage_alerts || false,
      unlimited_visibility: userRole.attributes.unlimited_visibility || false,
    };

    return {
      name: parsedResponse.data.attributes.name,
      email: parsedResponse.data.attributes.email,
      company: parsedResponse.data.attributes.company_name,
      dateJoined: parsedResponse.data.attributes.date_joined,
      permissions,
    };
  } catch (error: any) {
    throw new Error(error.message || "Network error or server unreachable");
  }
};

export async function logOut() {
  await signOut({ redirectTo: "/sign-in" });
}

export const validateTotp = async (formData: {
  email: string;
  password: string;
  totpCode: string;
  tenantId?: string;
}) => {
  const url = new URL(`${apiBaseUrl}/totp/validate`);

  const bodyData = {
    data: {
      type: "totp-validate",
      attributes: {
        email: formData.email,
        password: formData.password,
        totp_code: formData.totpCode,
        ...(formData.tenantId && { tenant_id: formData.tenantId }),
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
    if (!response.ok) return null;

    return {
      accessToken: parsedResponse.data.attributes.access,
      refreshToken: parsedResponse.data.attributes.refresh,
    };
  } catch (_error) {
    return null;
  }
};
