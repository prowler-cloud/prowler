import { RouterContext } from "next/dist/shared/lib/router-context.shared-runtime";
import type { NextRouter } from "next/router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { page, userEvent } from "vitest/browser";

import { render } from "@/__tests__/render-browser";

import { ResourceCountCell } from "./resource-count-cell";

const initialUrl = window.location.href;

afterEach(() => {
  window.history.replaceState({}, "", initialUrl);
});

describe("scan resource count navigation", () => {
  it.each(["click", "keyboard"])(
    "opens only the selected scan scope through %s activation",
    async (activation) => {
      // Given - The Next router boundary updates real browser history.
      window.history.replaceState(
        {},
        "",
        "/scans?filter[provider]=stale-provider&filter[inserted_at]=2024-01-01&page=3",
      );
      const push: NextRouter["push"] = vi.fn(async (url) => {
        window.history.pushState({}, "", String(url));
        return true;
      });
      const router: NextRouter = {
        route: "/scans",
        pathname: "/scans",
        query: {},
        asPath: "/scans",
        basePath: "",
        isLocaleDomain: false,
        isFallback: false,
        isReady: true,
        isPreview: false,
        push,
        replace: vi.fn(async () => true),
        reload: vi.fn(),
        back: vi.fn(),
        forward: vi.fn(),
        prefetch: vi.fn(async () => undefined),
        beforePopState: vi.fn(),
        events: { on: vi.fn(), off: vi.fn(), emit: vi.fn() },
      };
      await render(
        <RouterContext.Provider value={router}>
          <ResourceCountCell count={1234} scanId="older-scan" />
        </RouterContext.Provider>,
      );
      const link = page.getByRole("link", { name: "1,234" });

      // When
      if (activation === "keyboard") {
        await userEvent.tab();
        await expect.element(link).toHaveFocus();
        await userEvent.keyboard("{Enter}");
      } else {
        await link.click();
      }

      // Then
      expect(push).toHaveBeenCalledOnce();
      expect(window.location.pathname).toBe("/resources");
      expect(
        Array.from(new URLSearchParams(window.location.search).entries()),
      ).toEqual([["filter[scan]", "older-scan"]]);
    },
  );
});
