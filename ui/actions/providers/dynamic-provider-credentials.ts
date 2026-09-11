"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { parseRegistryCredentialSchema } from "@/lib/provider-credentials/provider-credential-schema";
import { validateCredentialValues } from "@/lib/provider-credentials/provider-credential-values";
import { isKnownProviderType } from "@/types/providers";

import { getProviderSchemas } from "./provider-schemas";

const resourceId = z.string().regex(/^[a-zA-Z0-9_-]{1,100}$/);
const inputSchema = z.object({
  providerId: resourceId,
  secretType: z.string().min(1),
  secret: z.unknown(),
});
const accountSchema = z.object({
  data: z.object({
    id: resourceId,
    attributes: z.object({ provider: z.string() }),
    relationships: z.object({
      secret: z.object({ data: z.object({ id: resourceId }).nullable() }),
    }),
  }),
});

export type DynamicCredentialsResult =
  | { status: "saved"; secretId: string }
  | { status: "invalid"; errors: Record<string, string> }
  | { status: "access_denied" | "schema_unavailable" | "error" };

export async function saveDynamicProviderCredentials(
  input: unknown,
): Promise<DynamicCredentialsResult> {
  const parsed = inputSchema.safeParse(input);
  if (!parsed.success)
    return {
      status: "invalid",
      errors: { _form: "Check the provider and credential fields." },
    };
  const { providerId, secretType, secret } = parsed.data;
  try {
    const headers = await getAuthHeaders({ contentType: true });
    const accountResponse = await fetch(
      `${apiBaseUrl}/providers/${encodeURIComponent(providerId)}`,
      { headers, cache: "no-store" },
    );
    if (accountResponse.status === 401 || accountResponse.status === 403)
      return { status: "access_denied" };
    if (!accountResponse.ok) return { status: "error" };
    const account = accountSchema.safeParse(await accountResponse.json());
    if (
      !account.success ||
      account.data.data.id !== providerId ||
      isKnownProviderType(account.data.data.attributes.provider)
    )
      return { status: "error" };
    const schemas = await getProviderSchemas(
      account.data.data.attributes.provider,
    );
    if (schemas.status === "access_denied") return { status: "access_denied" };
    if (
      schemas.status !== "success" ||
      !Object.hasOwn(schemas.secretTypes, secretType)
    )
      return { status: "schema_unavailable" };
    const schema = parseRegistryCredentialSchema(
      schemas.secretTypes[secretType],
    );
    if (!schema) return { status: "schema_unavailable" };
    const validated = validateCredentialValues(schema, secret);
    if (!validated.valid)
      return { status: "invalid", errors: validated.errors };

    // Read the relationship again on every save so retries update a secret that
    // was already created, including after a lost response.
    const secretId = account.data.data.relationships.secret.data?.id;
    const response = await fetch(
      `${apiBaseUrl}/providers/secrets${secretId ? `/${encodeURIComponent(secretId)}` : ""}`,
      {
        method: secretId ? "PATCH" : "POST",
        headers,
        cache: "no-store",
        body: JSON.stringify({
          data: {
            type: "provider-secrets",
            ...(secretId
              ? { id: secretId }
              : {
                  relationships: {
                    provider: { data: { id: providerId, type: "providers" } },
                  },
                }),
            attributes: { secret_type: secretType, secret: validated.secret },
          },
        }),
      },
    );
    if (response.status === 401 || response.status === 403)
      return { status: "access_denied" };
    // API validation details may echo credential values. Keep them out of both
    // client errors and application logs.
    if (!response.ok) return { status: "error" };
    const saved = z
      .object({ data: z.object({ id: resourceId }) })
      .safeParse(await response.json());
    if (!saved.success) return { status: "error" };
    revalidatePath("/providers");
    return { status: "saved", secretId: saved.data.data.id };
  } catch {
    return { status: "error" };
  }
}
