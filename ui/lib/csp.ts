import { resolvePosthogUiHost } from "@/lib/posthog-hosts";

const POSTHOG_CSP_SOURCE = "https://*.posthog.com";

interface CspOptions {
  cloudEnabled: boolean;
  posthogEnabled: boolean;
  posthogKey: string | null;
  posthogIngestionHost: string | null;
  posthogUiHost: string | null;
  posthogToolbarEnabled: boolean;
}

const getPosthogToolbarUiSource = (
  ingestionHost: string,
  configuredUiHost: string | null,
): string => {
  try {
    const resolvedUiHost = resolvePosthogUiHost(
      ingestionHost,
      configuredUiHost,
    );
    const url = new URL(resolvedUiHost);
    const isHttp = url.protocol === "http:" || url.protocol === "https:";
    const coveredByCloudWildcard =
      url.protocol === "https:" && url.hostname.endsWith(".posthog.com");

    return isHttp && !coveredByCloudWildcard ? ` ${url.origin}` : "";
  } catch {
    return "";
  }
};

export function getCspHeader({
  cloudEnabled,
  posthogEnabled,
  posthogKey,
  posthogIngestionHost,
  posthogUiHost,
  posthogToolbarEnabled,
}: CspOptions): string {
  const allowPosthog =
    cloudEnabled &&
    posthogEnabled &&
    Boolean(posthogKey && posthogIngestionHost);
  const posthogSource = allowPosthog ? ` ${POSTHOG_CSP_SOURCE}` : "";
  const allowPosthogToolbar = allowPosthog && posthogToolbarEnabled;
  const toolbarUiSource =
    allowPosthogToolbar && posthogIngestionHost
      ? getPosthogToolbarUiSource(posthogIngestionHost, posthogUiHost)
      : "";
  const toolbarPosthogSource = allowPosthogToolbar
    ? ` ${POSTHOG_CSP_SOURCE}${toolbarUiSource}`
    : "";
  const toolbarWorkerSource = allowPosthogToolbar
    ? "worker-src 'self' blob: data:;"
    : "";
  const toolbarMediaSource = allowPosthogToolbar
    ? `media-src 'self' ${POSTHOG_CSP_SOURCE}${toolbarUiSource};`
    : "";
  const frameAncestors = allowPosthogToolbar
    ? `'self' ${POSTHOG_CSP_SOURCE}${toolbarUiSource}`
    : "'none'";

  return `
  default-src 'self';
  script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com https://www.googletagmanager.com https://browser.sentry-cdn.com${posthogSource}${toolbarUiSource};
  connect-src 'self' https://api.iconify.design https://api.simplesvg.com https://api.unisvg.com https://js.stripe.com https://www.googletagmanager.com https://*.sentry.io https://*.ingest.sentry.io${posthogSource}${toolbarUiSource};
  img-src 'self' https://www.google-analytics.com https://www.googletagmanager.com${posthogSource}${toolbarUiSource};
  font-src 'self'${toolbarPosthogSource};
  style-src 'self' 'unsafe-inline'${toolbarPosthogSource};
  ${toolbarMediaSource}
  ${toolbarWorkerSource}
  frame-src 'self' https://js.stripe.com https://www.googletagmanager.com${posthogSource}${toolbarUiSource};
  frame-ancestors ${frameAncestors};
`.replace(/\n/g, "");
}
