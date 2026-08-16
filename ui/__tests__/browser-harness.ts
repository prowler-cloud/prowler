/**
 * Base class for browser-mode page test harnesses.
 *
 * Owns the generic DOM / wait / interaction plumbing every page harness needs,
 * so concrete harnesses (providers, attack-paths, …) only declare their own
 * domain vocabulary. The DOM / wait / interaction primitives are `protected` —
 * subclasses build their semantic API on top of them and tests don't reach
 * them directly. The public members are the deliberate exceptions: `user`
 * (harness tests spy on it) and the request-tracking assertion helpers
 * (`requestLog`, `countRequests`, `lastRequestBody`) that page harnesses expose
 * as domain vocab.
 *
 * Mount-agnostic on purpose: some pages are mounted by their harness, others
 * (attack-paths) are rendered by the test directly, so a `render` here would
 * only serve half the call sites. Mounting lives in `render-browser.tsx`, which
 * wraps every render in the shared app shell (`app-shell.tsx`) — both kinds of
 * call site reach it.
 *
 * Request tracking is opt-in via `trackRequests(worker)`, and unregisters
 * itself when the test ends.
 */
import type { SetupWorker } from "msw/browser";
import { onTestFinished, vi } from "vitest";
import { userEvent } from "vitest/browser";

type RequestStartListener = (event: { request: Request }) => void;

/**
 * The predicate stayed falsy for the whole timeout. `waitForOrNull` swallows
 * only this, so a throwing predicate still surfaces as the bug it is.
 */
class WaitForPending extends Error {}

export abstract class BrowserHarness<TFixture> {
  readonly user = userEvent;

  /**
   * Every request MSW saw since `trackRequests` was wired, for assertions. The
   * entry keeps a clone, so a payload assertion can read a body the app's own
   * fetch already consumed.
   */
  readonly requestLog: Array<{
    method: string;
    url: string;
    request: Request;
  }> = [];

  private trackedWorker: SetupWorker | null = null;
  private requestListener: RequestStartListener | null = null;

  constructor(readonly fixture: TFixture) {}

  // --- Request tracking (opt-in) ------------------------------------------

  /** Start recording MSW requests into `requestLog`. Call once, after mounting. */
  protected trackRequests(worker: SetupWorker): void {
    const listener: RequestStartListener = ({ request }) => {
      this.requestLog.push({
        method: request.method,
        url: request.url,
        request: request.clone(),
      });
    };
    this.trackedWorker = worker;
    this.requestListener = listener;
    worker.events.on("request:start", listener);
    // The worker is module-level and shared across harnesses, so listeners
    // would otherwise accumulate run over run. Drop only this harness's
    // listener when the test ends — clearing the emitter would also silence
    // listeners another harness or diagnostic owns.
    onTestFinished(() => this.untrackRequests());
  }

  private untrackRequests(): void {
    const worker = this.trackedWorker;
    const listener = this.requestListener;
    if (!worker || !listener) return;

    worker.events.removeListener("request:start", listener);
    this.trackedWorker = null;
    this.requestListener = null;
  }

  countRequests(method: string, pathIncludes: string): number {
    return this.requestLog.filter(
      (r) => r.method === method && r.url.includes(pathIncludes),
    ).length;
  }

  /** Parsed JSON body of the most recent request matching method + path. */
  async lastRequestBody<T = unknown>(
    method: string,
    pathIncludes: string,
  ): Promise<T | null> {
    const entry = [...this.requestLog]
      .reverse()
      .find((r) => r.method === method && r.url.includes(pathIncludes));
    return entry ? ((await entry.request.clone().json()) as T) : null;
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

  /**
   * Wait until the predicate returns truthy and return that value. `label`
   * names what was awaited, so the timeout message identifies the caller.
   */
  protected async waitFor<T>(
    fn: () => T | null | undefined | false,
    timeoutMs = 5000,
    label?: string,
    intervalMs = 30,
  ): Promise<T> {
    // `vi.waitFor` rejects with the *last* callback error, so a predicate that
    // throws and then goes falsy would time out as a bare `WaitForPending`.
    // Keep its error so the sentinel never outranks a real one.
    let predicateThrew = false;
    let predicateError: unknown;

    try {
      return (await vi.waitFor(
        () => {
          let v: T | null | undefined | false;
          try {
            v = fn();
          } catch (error) {
            predicateThrew = true;
            predicateError = error;
            throw error;
          }
          if (!v) {
            throw new WaitForPending(
              `waitFor: timed out waiting for ${label ?? "predicate to be truthy"}`,
            );
          }
          return v;
        },
        { timeout: timeoutMs, interval: intervalMs },
      )) as T;
    } catch (error) {
      if (error instanceof WaitForPending && predicateThrew) {
        throw predicateError;
      }
      throw error;
    }
  }

  /**
   * Like `waitFor`, but resolves to null when the predicate never became
   * truthy. A throwing predicate still propagates.
   */
  protected async waitForOrNull<T>(
    fn: () => T | null | undefined | false,
    timeoutMs = 5000,
    label?: string,
  ): Promise<T | null> {
    try {
      return await this.waitFor(fn, timeoutMs, label);
    } catch (error) {
      if (error instanceof WaitForPending) return null;
      throw error;
    }
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

  /**
   * Click a dropdown/menu item (rendered in a Radix portal) by its label.
   *
   * Native click, not `user.click`: the portal animates in while the row behind
   * it re-renders, and Playwright rejects the element as unstable or detached.
   * A native click needs no stability check but is lost silently on a detached
   * node, so re-resolve each attempt and stop once the menu unmounts.
   *
   * Only for items that close the menu — a checkbox, radio or submenu item
   * needs its own helper.
   */
  protected async clickMenuItem(name: RegExp): Promise<void> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      // The menu is already mounted after the first attempt, so keep the
      // re-resolve short to bound the retry tail inside the test budget.
      const item = await this.waitFor(
        () => this.byRoleName("menuitem", name),
        attempt === 0 ? 5000 : 500,
        `menu item ${name}`,
      );
      item.click();
      const closed = await this.waitForOrNull(
        () => this.q('[role="menu"]') === null,
        2000,
        `the menu to close after clicking ${name}`,
      );
      if (closed) return;
    }
    throw new Error(
      `clickMenuItem: menu stayed open after clicking ${name} 3 times`,
    );
  }
}
