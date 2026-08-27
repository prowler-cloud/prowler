const POSTHOG_CSP_SOURCE = "https://*.posthog.com";

interface CspOptions {
  cloudEnabled: boolean;
  posthogEnabled: boolean;
  posthogKey: string | null;
  posthogIngestionHost: string | null;
  posthogToolbarEnabled: boolean;
}

export function getCspHeader({
  cloudEnabled,
  posthogEnabled,
  posthogKey,
  posthogIngestionHost,
  posthogToolbarEnabled,
}: CspOptions): string {
  const allowPosthog =
    cloudEnabled &&
    posthogEnabled &&
    Boolean(posthogKey && posthogIngestionHost);
  const posthogSource = allowPosthog ? ` ${POSTHOG_CSP_SOURCE}` : "";
  const allowPosthogToolbar = allowPosthog && posthogToolbarEnabled;
  const toolbarPosthogSource = allowPosthogToolbar
    ? ` ${POSTHOG_CSP_SOURCE}`
    : "";
  const toolbarWorkerSource = allowPosthogToolbar
    ? "worker-src 'self' blob: data:;"
    : "";
  const toolbarMediaSource = allowPosthogToolbar
    ? `media-src 'self' ${POSTHOG_CSP_SOURCE};`
    : "";
  const frameAncestors = allowPosthogToolbar
    ? `'self' ${POSTHOG_CSP_SOURCE}`
    : "'none'";

  return `
  default-src 'self';
  script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com https://www.googletagmanager.com https://browser.sentry-cdn.com${posthogSource};
  connect-src 'self' https://api.iconify.design https://api.simplesvg.com https://api.unisvg.com https://js.stripe.com https://www.googletagmanager.com https://*.sentry.io https://*.ingest.sentry.io${posthogSource};
  img-src 'self' https://www.google-analytics.com https://www.googletagmanager.com${posthogSource};
  font-src 'self'${toolbarPosthogSource};
  style-src 'self' 'unsafe-inline'${toolbarPosthogSource};
  ${toolbarMediaSource}
  ${toolbarWorkerSource}
  frame-src 'self' https://js.stripe.com https://www.googletagmanager.com${posthogSource};
  frame-ancestors ${frameAncestors};
`.replace(/\n/g, "");
}
