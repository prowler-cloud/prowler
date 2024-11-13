"use server";

import { auth } from "@/auth.config";
import { getErrorMessage, parseStringify } from "@/lib";

export const sendInvite = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const email = formData.get("email");
  const url = new URL(`${keyServer}/tenants/invitations`);

  const body = JSON.stringify({
    data: {
      type: "Invitation",
      attributes: {
        email,
      },
      relationships: {},
    },
  });

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
      body,
    });
    const data = await response.json();

    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const getInvitationInfoById = async (invitationId: string) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/tenants/invitations/${invitationId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });

    const data = await response.json();
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};
