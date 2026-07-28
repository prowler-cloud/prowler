/**
 * Base class for browser-mode page test harnesses.
 *
 * Owns the generic DOM / wait / interaction plumbing every page harness needs,
 * so concrete harnesses (providers, attack-paths, …) only declare their own
 * domain vocabulary. The DOM / wait / interaction primitives are `protected` —
 * subclasses build their semantic API on top of them and tests don't reach
 * them directly. The public members are the deliberate exceptions: `user`
 * (harness tests spy on it) and the request-tracking assertion helpers
 * (`requestLog`, `countRequests`) that page harnesses expose as domain vocab.
 *
 * Mount-agnostic on purpose — some harnesses mount the page themselves, others
 * are mounted by the test — so there is no `render` here. Request tracking is
 * opt-in via `trackRequests(worker)`.
 */
import type { SetupWorker } from "msw/browser";
import { vi } from "vitest";
import { userEvent } from "vitest/browser";

export abstract class BrowserHarness<TFixture> {
  readonly user = userEvent;

  /** Every request MSW saw since `trackRequests` was wired, for assertions. */
  readonly requestLog: Array<{ method: string; url: string }> = [];

  constructor(readonly fixture: TFixture) {}

  // --- Request tracking (opt-in) ------------------------------------------

  /** Start recording MSW requests into `requestLog`. Call once, after mounting. */
  protected trackRequests(worker: SetupWorker): void {
    // Clear only our own `request:start` listeners from a prior harness on the
    // shared worker — not every listener on the public event emitter.
    worker.events.removeAllListeners("request:start");
    worker.events.on("request:start", ({ request }) => {
      this.requestLog.push({ method: request.method, url: request.url });
    });
  }

  countRequests(method: string, pathIncludes: string): number {
    return this.requestLog.filter(
      (r) => r.method === method && r.url.includes(pathIncludes),
    ).length;
  }

  // --- Low-level DOM ------------------------------------------------------

  protected get container(): HTMLElement {
    return document.body;
  }

  protected q(selector: string): HTMLElement | null {
    return this.container.querySelector<HTMLElement>(selector);
  }

  protected byRoleName(
    role: string,
    name: RegExp,
    scope: ParentNode = document,
  ): HTMLElement | null {
    const explicit = Array.from(
      scope.querySelectorAll<HTMLElement>(`[role="${role}"]`),
    ).find((el) => name.test(el.textContent ?? ""));
    if (explicit) return explicit;
    // A native <button> exposes role "button" implicitly, without the
    // attribute — so it isn't matched by the `[role="button"]` query above.
    if (role === "button") {
      return (
        Array.from(scope.querySelectorAll<HTMLElement>("button")).find(
          (el) => !el.hasAttribute("role") && name.test(el.textContent ?? ""),
        ) ?? null
      );
    }
    return null;
  }

  protected buttonByText(
    name: RegExp,
    scope: ParentNode = document,
  ): HTMLButtonElement | null {
    return (
      Array.from(scope.querySelectorAll<HTMLButtonElement>("button")).find(
        (b) => name.test(b.textContent ?? ""),
      ) ?? null
    );
  }

  protected inputByName(name: string): HTMLInputElement | null {
    return this.q(`input[name="${name}"]`) as HTMLInputElement | null;
  }

  protected containsText(pattern: RegExp): boolean {
    return pattern.test(this.container.textContent ?? "");
  }

  // --- Sync helpers -------------------------------------------------------

  /** Wait until the predicate returns truthy and return that value. */
  protected async waitFor<T>(
    fn: () => T | null | undefined | false,
    timeoutMs = 5000,
    intervalMs = 30,
  ): Promise<T> {
    return vi.waitFor(
      () => {
        const v = fn();
        if (!v) throw new Error("waitFor predicate not yet truthy");
        return v;
      },
      { timeout: timeoutMs, interval: intervalMs },
    ) as Promise<T>;
  }

  protected async waitForText(
    pattern: RegExp,
    timeoutMs = 5000,
  ): Promise<void> {
    await this.waitFor(() => this.containsText(pattern), timeoutMs);
  }

  protected async waitForButton(
    name: RegExp,
    timeoutMs = 5000,
  ): Promise<HTMLButtonElement> {
    return this.waitFor(() => {
      const btn = this.buttonByText(name);
      return btn && !btn.disabled ? btn : null;
    }, timeoutMs);
  }

  /**
   * Sleep for a fixed duration to let a CSS/layout transition settle. Public
   * because a few flows assert on animation-tail state that has no queryable
   * settled signal; prefer waiting on an observable post-condition when one
   * exists.
   */
  async waitForTransition(ms = 350): Promise<void> {
    await new Promise((r) => setTimeout(r, ms));
  }

  // --- Interactions -------------------------------------------------------

  /** Click via user-event, optionally falling back to a native DOM click. */
  protected async clickElement(
    element: HTMLElement,
    options?: { fallbackToDomClick?: boolean },
  ): Promise<void> {
    try {
      await this.user.click(element);
    } catch (error) {
      if (!options?.fallbackToDomClick) throw error;
      element.click();
    }
  }

  protected async clickButton(name: RegExp): Promise<void> {
    const btn = await this.waitForButton(name);
    await this.user.click(btn);
  }

  /** Click a dropdown/menu item (rendered in a Radix portal) by its label. */
  protected async clickMenuItem(name: RegExp): Promise<void> {
    const item = await this.waitFor(() => this.byRoleName("menuitem", name));
    await this.user.click(item);
  }
}
