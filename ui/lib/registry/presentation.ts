import { readEnv } from "@/lib/runtime-env";

/** Accept public HTTP URLs only; never expose URL credentials or CSP syntax. */
function parsePublicUrl(value?: string | null): URL | undefined {
  if (!value || /[\s;]/.test(value)) return;
  try {
    const url = new URL(value);
    if (
      (url.protocol === "https:" || url.protocol === "http:") &&
      !url.username &&
      !url.password
    )
      return url;
  } catch {
    return;
  }
}

export function getRegistryPresentation(
  registryUrl?: string | null,
  mediaUrl?: string | null,
) {
  const registry = parsePublicUrl(registryUrl);
  const media = parsePublicUrl(mediaUrl);
  return {
    registryUrl: registry?.href,
    imageOrigins: Array.from(
      new Set(
        [registry?.origin, media?.origin].filter((origin): origin is string =>
          Boolean(origin),
        ),
      ),
    ),
  };
}

/** Same Registry base URL the backend installs artifacts from. */
export function readRegistryPresentation() {
  return getRegistryPresentation(
    readEnv("PROWLER_REGISTRY_INDEX_URL"),
    readEnv("UI_REGISTRY_MEDIA_URL"),
  );
}
