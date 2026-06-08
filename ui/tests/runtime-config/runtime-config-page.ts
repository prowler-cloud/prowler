import { expect, Locator, Page, Request } from "@playwright/test";

import { BasePage } from "../base-page";

/** Must match RUNTIME_CONFIG_SCRIPT_ID in `lib/runtime-config.shared.ts`. */
export const RUNTIME_CONFIG_SCRIPT_ID = "__PROWLER_RUNTIME_CONFIG__";

/** Keys the runtime data island is expected to expose (the allowlist). */
export const RUNTIME_CONFIG_KEYS = [
  "sentryDsn",
  "sentryEnvironment",
  "googleTagManagerId",
  "apiBaseUrl",
  "apiDocsUrl",
  "posthogKey",
  "posthogHost",
  "reoDevClientId",
] as const;

/**
 * Page object for the runtime public-config data island. The island is rendered
 * into `<head>` by both root layouts, so any unauthenticated route works; the
 * sign-in page is used because it needs no session.
 */
export class RuntimeConfigPage extends BasePage {
  readonly island: Locator;

  constructor(page: Page) {
    super(page);
    this.island = page.locator(`script#${RUNTIME_CONFIG_SCRIPT_ID}`);
  }

  async goto(): Promise<void> {
    await super.goto("/sign-in");
  }

  /** Parsed island JSON, or null when the island is missing/malformed. */
  async readConfig(): Promise<Record<string, unknown> | null> {
    return this.page.evaluate((id) => {
      const el = document.getElementById(id);
      if (!el?.textContent) return null;
      try {
        return JSON.parse(el.textContent) as Record<string, unknown>;
      } catch {
        return null;
      }
    }, RUNTIME_CONFIG_SCRIPT_ID);
  }

  /** DSN the browser Sentry client initialized with, or null if uninitialized. */
  async sentryInitializedDsn(): Promise<string | null> {
    return this.page.evaluate(() => {
      const sentry = (window as unknown as { __SENTRY__?: unknown }).__SENTRY__;
      if (!sentry || typeof sentry !== "object") return null;
      const hub = sentry as {
        getClient?: () => unknown;
        hub?: { getClient?: () => unknown };
      };
      const client = (hub.getClient?.() ?? hub.hub?.getClient?.()) as
        | { getOptions?: () => { dsn?: string } }
        | undefined;
      return client?.getOptions?.().dsn ?? null;
    });
  }

  async verifyIslandInHead(): Promise<void> {
    // type="application/json" ⇒ inert, not governed by CSP script-src.
    await expect(this.island).toHaveAttribute("type", "application/json");
    const parentTag = await this.island.evaluate(
      (el) => el.parentElement?.tagName.toLowerCase() ?? "",
    );
    expect(parentTag).toBe("head");
  }

  /**
   * The island must precede the first ordered (non-`async`) bundle
   * `<script src>` — that bundle is the client entry calling
   * getRuntimeConfigClient(), so the island must exist before it runs. Next.js's
   * `async` chunk-preloads load out of order and don't read the config, so they
   * are excluded.
   */
  async verifyIslandPrecedesClientBundle(): Promise<void> {
    const precedes = await this.page.evaluate((id) => {
      const scripts = Array.from(document.querySelectorAll("script"));
      const islandIndex = scripts.findIndex((s) => s.id === id);
      if (islandIndex === -1) return false;
      const firstOrderedBundleIndex = scripts.findIndex(
        (s) => s.src && !s.async,
      );
      return (
        firstOrderedBundleIndex === -1 || islandIndex < firstOrderedBundleIndex
      );
    }, RUNTIME_CONFIG_SCRIPT_ID);
    expect(precedes).toBe(true);
  }

  /**
   * Reload the page while recording any request whose URL contains one of the
   * given host fragments. Returns the matching URLs (empty ⇒ zero egress).
   */
  async thirdPartyRequestsOnReload(hostFragments: string[]): Promise<string[]> {
    const hits: string[] = [];
    const listener = (req: Request) => {
      const url = req.url();
      if (hostFragments.some((fragment) => url.includes(fragment))) {
        hits.push(url);
      }
    };
    this.page.on("request", listener);
    await this.page.reload({ waitUntil: "load" });
    this.page.off("request", listener);
    return hits;
  }

  async verifyGoogleTagManagerNotRendered(): Promise<void> {
    await expect(
      this.page.locator('script[src*="googletagmanager.com"]'),
    ).toHaveCount(0);
  }
}
