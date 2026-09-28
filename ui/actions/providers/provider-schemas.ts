"use server";

import { auth } from "@/auth.config";
import { apiBaseUrl } from "@/lib";
import {
  PROVIDER_SCHEMA_STATUS,
  type ProviderSchemasResult,
} from "@/types/provider-schema";

import {
  adaptProviderSchemas,
  normalizeProviderType,
} from "./provider-schemas.adapter";

export async function getProviderSchemas(
  providerType: unknown,
): Promise<ProviderSchemasResult> {
  const normalizedProviderType = normalizeProviderType(providerType);
  if (!normalizedProviderType) return { status: PROVIDER_SCHEMA_STATUS.ERROR };

  let accessToken: string | undefined;
  try {
    accessToken = (await auth())?.accessToken?.trim();
  } catch {
    return { status: PROVIDER_SCHEMA_STATUS.ERROR };
  }
  if (!accessToken) return { status: PROVIDER_SCHEMA_STATUS.ACCESS_DENIED };

  let response: Response;
  try {
    response = await fetch(
      `${apiBaseUrl}/provider-schemas/${encodeURIComponent(normalizedProviderType)}`,
      {
        cache: "no-store",
        headers: {
          Accept: "application/vnd.api+json",
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );
  } catch {
    return { status: PROVIDER_SCHEMA_STATUS.ERROR };
  }

  if (response.status === 401 || response.status === 403) {
    return { status: PROVIDER_SCHEMA_STATUS.ACCESS_DENIED };
  }
  if (response.status === 404) {
    return { status: PROVIDER_SCHEMA_STATUS.NOT_FOUND };
  }
  if (response.status === 409) {
    return { status: PROVIDER_SCHEMA_STATUS.UNAVAILABLE };
  }
  if (!response.ok) return { status: PROVIDER_SCHEMA_STATUS.ERROR };

  const schema = adaptProviderSchemas(
    await response.json().catch(() => undefined),
    normalizedProviderType,
  );
  return schema ?? { status: PROVIDER_SCHEMA_STATUS.MALFORMED };
}
