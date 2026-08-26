/**
 * Shared client shell for browser-mode page tests.
 *
 * Mirrors the production shell: `app/(prowler)/layout.tsx` (the source of truth
 * — keep this in step with it) renders `<Providers themeProps={{ attribute:
 * "class", defaultTheme: "dark" }}>` — i.e. `app/providers.tsx`'s
 * `SessionProvider` + `next-themes` provider — with `<Toaster />` mounted inside
 * it. Pages under test therefore get the same session/theme context and the same
 * toast host they get in production, instead of each harness hand-rolling a
 * subset.
 *
 * Mirrored rather than composed from `app/providers.tsx` on purpose: that
 * component hardcodes a session-less `SessionProvider`, which fetches
 * `/api/auth/session` on mount. There is no Next auth route in browser mode and
 * MSW is configured with `onUnhandledRequest: "error"`, so that request fails
 * the test. Wrapping it in an outer `SessionProvider` doesn't help — the inner,
 * session-less one is the provider the tree actually consumes.
 */
import type { Session } from "next-auth";
import { SessionProvider } from "next-auth/react";
import { ThemeProvider } from "next-themes";
import type { PropsWithChildren } from "react";

import { Toaster } from "@/components/shadcn/toast/Toaster";

const TENANT_ID = "11111111-2222-4333-8444-555555555555";

/**
 * Default fake session. Supplying one keeps `SessionProvider` from fetching
 * `/api/auth/session`; the token is what the server actions send to MSW. Typed
 * as the app's augmented `Session` (see `nextauth.d.ts`) so a change to the
 * fields the pages read fails here instead of at runtime.
 */
const TEST_SESSION: Session = {
  tenantId: TENANT_ID,
  accessToken: "test-access-token",
  expires: "2999-01-01T00:00:00Z",
};

interface TestAppShellProps extends PropsWithChildren {
  /** Override the default fake session (e.g. a different tenant). */
  session?: Session;
}

export function TestAppShell({
  children,
  session = TEST_SESSION,
}: TestAppShellProps) {
  return (
    <SessionProvider session={session}>
      <ThemeProvider attribute="class" defaultTheme="dark">
        {children}
        <Toaster />
      </ThemeProvider>
    </SessionProvider>
  );
}
