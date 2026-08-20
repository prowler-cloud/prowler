import { z } from "zod";

import { apiBaseUrl } from "@/lib";
import { PERMISSION_KEY, type RolePermissionAttributes } from "@/types/users";

const currentUserDocumentSchema = z.object({
  data: z.object({
    type: z.literal("users"),
    id: z.string().min(1),
    attributes: z.object({
      name: z.string(),
      email: z.string(),
      company_name: z.string().optional(),
      date_joined: z.string().optional(),
    }),
  }),
  included: z.array(
    z.object({
      type: z.literal("roles"),
      id: z.string().min(1),
      attributes: z.record(z.string(), z.unknown()),
    }),
  ),
});

export interface CurrentUser {
  name: string;
  email: string;
  company?: string;
  dateJoined?: string;
  permissions: RolePermissionAttributes;
  manageRegistry: true | false | undefined;
}

const toPermissions = (
  attributes: Record<string, unknown>,
): RolePermissionAttributes =>
  Object.fromEntries(
    Object.values(PERMISSION_KEY).map((key) => [key, attributes[key] === true]),
  ) as RolePermissionAttributes;

export async function fetchCurrentUser(
  accessToken: string,
  options: { signal?: AbortSignal } = {},
): Promise<CurrentUser> {
  if (!accessToken.trim()) throw new Error("Current user token is required");

  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl}/users/me?include=roles`, {
      method: "GET",
      cache: "no-store",
      signal: options.signal,
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${accessToken}`,
      },
    });
  } catch {
    throw new Error("Unable to fetch current user");
  }

  if (!response.ok) throw new Error("Unable to fetch current user");

  const parsed = currentUserDocumentSchema.safeParse(
    await response.json().catch(() => undefined),
  );
  if (!parsed.success) throw new Error("Malformed current user response");

  const [role] = parsed.data.included;
  if (parsed.data.included.length !== 1 || !role) {
    throw new Error("Ambiguous current user role");
  }

  const attributes = role.attributes;
  const manageRegistry = attributes.manage_registry;
  return {
    name: parsed.data.data.attributes.name,
    email: parsed.data.data.attributes.email,
    company: parsed.data.data.attributes.company_name,
    dateJoined: parsed.data.data.attributes.date_joined,
    permissions: toPermissions(attributes),
    manageRegistry:
      typeof manageRegistry === "boolean" ? manageRegistry : undefined,
  };
}
