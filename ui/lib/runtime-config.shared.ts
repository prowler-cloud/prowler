// Side-effect-free shape shared by the server and client readers (no
// server-only code, so it's safe to import from the client bundle).
export interface RuntimePublicConfig {
  sentryDsn: string | null;
  sentryEnvironment: string | null;
  googleTagManagerId: string | null;
  apiBaseUrl: string | null;
  apiDocsUrl: string | null;
  posthogKey: string | null; // reserved
  posthogHost: string | null; // reserved
  reoDevClientId: string | null; // reserved
}

export const RUNTIME_CONFIG_SCRIPT_ID = "__PROWLER_RUNTIME_CONFIG__";

// All-null fallback (SSR or parse failure).
export const EMPTY_RUNTIME_PUBLIC_CONFIG: RuntimePublicConfig = {
  sentryDsn: null,
  sentryEnvironment: null,
  googleTagManagerId: null,
  apiBaseUrl: null,
  apiDocsUrl: null,
  posthogKey: null,
  posthogHost: null,
  reoDevClientId: null,
};
