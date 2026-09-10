import { afterEach, describe, expect, it } from "vitest";
import { page } from "vitest/browser";
import { render } from "vitest-browser-react";

import { Toaster } from "./Toaster";
import { toast } from "./use-toast";

const MESSAGE =
  "Provider connection failed. Check your credentials and try connecting again.";
const LONG_URL = `https://example.com/${"provider-identifier".repeat(16)}`;
const DESCRIPTION = `${MESSAGE}\n${LONG_URL}\nExplicit final line`;

describe("toast text wrapping", () => {
  afterEach(async () => {
    await page.viewport(1280, 800);
  });

  it.each([1280, 393])(
    "preserves words and contains long URLs at %ipx",
    async (width) => {
      // Given
      await page.viewport(width, 800);
      toast({
        title: "Connection test failed",
        description: DESCRIPTION,
        duration: Infinity,
      });

      // When
      const screen = await render(<Toaster />);
      const description = screen.getByText(DESCRIPTION, { exact: true });
      await expect.element(description).toBeVisible();
      const element = description.element();
      const text = element.firstChild!;
      const range = document.createRange();

      // Then: regular words fit on one line rather than breaking mid-word.
      for (const match of Array.from(MESSAGE.matchAll(/\S+/g))) {
        range.setStart(text, match.index);
        range.setEnd(text, match.index + match[0].length);
        expect(Array.from(range.getClientRects()), match[0]).toHaveLength(1);
      }

      // Long unbroken strings wrap without clipping or horizontal scrolling.
      range.setStart(text, MESSAGE.length + 1);
      range.setEnd(text, MESSAGE.length + 1 + LONG_URL.length);
      const urlLines = Array.from(range.getClientRects());
      expect(urlLines.length).toBeGreaterThan(1);
      const bounds = element.getBoundingClientRect();
      expect(urlLines.every((line) => line.right <= bounds.right + 1)).toBe(
        true,
      );
      expect(element.scrollWidth).toBeLessThanOrEqual(element.clientWidth);

      // Explicit line breaks are preserved and tall descriptions remain scrollable.
      range.setStart(text, DESCRIPTION.indexOf("Explicit"));
      range.setEnd(text, DESCRIPTION.length);
      expect(range.getBoundingClientRect().top).toBeGreaterThan(
        urlLines.at(-1)!.top,
      );
      expect(getComputedStyle(element).overflowY).toBe("auto");
      expect(element.clientHeight).toBeLessThanOrEqual(192);
      await page.screenshot();
    },
  );
});
