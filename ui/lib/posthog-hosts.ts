const POSTHOG_CLOUD_INGESTION_HOST = /^(eu|us)\.i\.posthog\.com$/i;

const stripTrailingSlash = (host: string): string => host.replace(/\/+$/, "");

export function resolvePosthogUiHost(
  ingestionHost: string,
  configuredUiHost: string | null,
): string {
  if (configuredUiHost) return stripTrailingSlash(configuredUiHost);

  const normalizedIngestionHost = stripTrailingSlash(ingestionHost);

  try {
    const url = new URL(normalizedIngestionHost);
    const match = url.hostname.match(POSTHOG_CLOUD_INGESTION_HOST);
    if (match) return `${url.protocol}//${match[1]}.posthog.com`;
  } catch {
    // Keep the configured value so posthog-js reports the invalid host.
  }

  return normalizedIngestionHost;
}
