"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { auth } from "@/auth.config";
import { getErrorMessage, parseStringify, wait } from "@/lib";

export const getInvitations = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const session = await auth();

  if (isNaN(Number(page)) || page < 1) redirect("/invitations");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/tenants/invitations`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const invitations = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await invitations.json();
    const parsedData = parseStringify(data);
    revalidatePath("/invitations");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching invitations:", error);
    return undefined;
  }
};

export const sendInvite = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const email = formData.get("email");
  const url = new URL(`${keyServer}/tenants/invitations`);

  const body = JSON.stringify({
    data: {
      type: "invitations",
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

export const updateInvite = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const invitationId = formData.get("invitationId");
  const invitationEmail = formData.get("invitationEmail");
  const expiresAt = formData.get("expires_at");

  const url = new URL(`${keyServer}/tenants/invitations/${invitationId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
      body: JSON.stringify({
        data: {
          type: "invitations",
          id: invitationId,
          attributes: {
            email: invitationEmail,
            ...(expiresAt && { expires_at: expiresAt }),
          },
        },
      }),
    });
    const data = await response.json();
    revalidatePath("/invitations");
    return parseStringify(data);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error updating invitation:", error);
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

export const revokeInvite = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const invitationId = formData.get("invitationId");
  const url = new URL(`${keyServer}/tenants/invitations/${invitationId}`);
  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await response.json();
    await wait(1000);
    revalidatePath("/invitations");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};
