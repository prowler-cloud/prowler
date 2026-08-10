const POSTHOG_CSP_SOURCE = "https://*.posthog.com";

interface CspOptions {
  cloudEnabled: boolean;
  posthogEnabled: boolean;
  posthogKey: string | null;
  posthogHost: string | null;
}

export function getCspHeader({
  cloudEnabled,
  posthogEnabled,
  posthogKey,
  posthogHost,
}: CspOptions): string {
  const allowPosthog =
    cloudEnabled && posthogEnabled && Boolean(posthogKey && posthogHost);
  const posthogSource = allowPosthog ? ` ${POSTHOG_CSP_SOURCE}` : "";

  return `
  default-src 'self';
  script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com https://www.googletagmanager.com https://browser.sentry-cdn.com${posthogSource};
  connect-src 'self' https://api.iconify.design https://api.simplesvg.com https://api.unisvg.com https://js.stripe.com https://www.googletagmanager.com https://*.sentry.io https://*.ingest.sentry.io${posthogSource};
  img-src 'self' https://www.google-analytics.com https://www.googletagmanager.com${posthogSource};
  font-src 'self';
  style-src 'self' 'unsafe-inline';
  frame-src 'self' https://js.stripe.com https://www.googletagmanager.com${posthogSource};
  frame-ancestors 'none';
`.replace(/\n/g, "");
}
