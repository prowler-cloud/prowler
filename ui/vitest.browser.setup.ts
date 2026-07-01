// Global stylesheet (Tailwind + design tokens) is imported by the Next.js
// layouts in the real app. Tests render the page in isolation, bypassing the
// layout, so without this import Tailwind classes resolve to nothing — the
// page collapses to unstyled HTML and stacked elements end up overlapping
// the graph nodes, blocking Playwright clicks. Pull the stylesheet directly
// so the test bundle gets the same CSS the production page receives.
import "@/styles/globals.css";

import { afterAll, afterEach, beforeAll, vi } from "vitest";

import { worker } from "./__tests__/msw/worker";

// Server Actions ("use server") are bundled by Vite as plain async functions
// — the directive is a Next.js compiler concept, not part of Vite. When the
// page invokes one, it runs in the browser and reaches `auth()` from
// next-auth, which calls `next/headers` (request-scoped AsyncLocalStorage
// only set up by Next's request handler) and throws "headers was called
// outside a request scope". That kills every action before it can hit
// MSW. Stub `auth.config` with a fake session so the action proceeds to
// `fetch()` and MSW takes over.
vi.mock("@/auth.config", () => ({
  auth: vi.fn(() => Promise.resolve({ accessToken: "test-access-token" })),
  signIn: vi.fn(),
  signOut: vi.fn(),
  handlers: {},
}));

// Next.js's App Router context (`useRouter`, `useSearchParams`, `usePathname`)
// is not available in vitest browser — there's no Next runtime mounting the
// providers. We back the hooks with the real `window.location` so navigating
// via `history.replaceState` in tests is enough to drive the page.
vi.mock("next/navigation", () => {
  const router = {
    push: vi.fn(),
    replace: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
    refresh: vi.fn(),
    prefetch: vi.fn(() => Promise.resolve()),
  };
  return {
    useSearchParams: () => new URLSearchParams(window.location.search),
    useRouter: () => router,
    usePathname: () => window.location.pathname,
    useParams: () => ({}),
    redirect: vi.fn(),
    notFound: vi.fn(),
  };
});

beforeAll(async () => {
  await worker.start({
    serviceWorker: { url: "/mockServiceWorker.js" },
    onUnhandledRequest: "error",
  });
});

afterEach(() => {
  worker.resetHandlers();
});

afterAll(() => {
  worker.stop();
});

// React Flow's pan/drag handlers dispatch pointer events that access
// `event.view.document` on the node. When user-event synthesises these
// events the `view` property can be null, producing harmless
// "Cannot read properties of null (reading 'document')" errors.
// Swallow only that specific unhandled error; everything else propagates.
const isReactFlowNullViewError = (reason: unknown): boolean => {
  const message =
    reason instanceof Error
      ? reason.message
      : typeof reason === "string"
        ? reason
        : "";
  return message.includes(
    "Cannot read properties of null (reading 'document')",
  );
};

window.addEventListener("error", (event) => {
  if (isReactFlowNullViewError(event.error)) {
    event.preventDefault();
    event.stopImmediatePropagation();
  }
});

window.addEventListener("unhandledrejection", (event) => {
  if (isReactFlowNullViewError(event.reason)) {
    event.preventDefault();
  }
});
