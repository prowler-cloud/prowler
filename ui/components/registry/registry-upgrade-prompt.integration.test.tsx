import { describe, expect, vi } from "vitest";
import { page } from "vitest/browser";

import { it } from "@/__tests__/fixtures";
import { render } from "@/__tests__/render-browser";

import { RegistryUpgradePrompt } from "./registry-upgrade-prompt";

vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ permissions: { manage_billing: true } }),
}));

const VIEWPORTS = [
  { name: "mobile", width: 390, height: 844 },
  { name: "tablet", width: 768, height: 1024 },
  { name: "desktop", width: 1280, height: 800 },
];

describe("Registry upgrade prompt (Cloudy)", () => {
  it.each(VIEWPORTS)(
    "renders no paid plan prompt on $name",
    async ({ width, height }) => {
      // Given
      await page.viewport(width, height);

      // When
      const screen = await render(
        <main
          data-testid="host"
          className="bg-bg-neutral-primary min-h-screen p-6"
        >
          <RegistryUpgradePrompt />
        </main>,
      );

      // Then
      await expect
        .element(screen.getByRole("button", { name: "Unlock Registry" }))
        .not.toBeInTheDocument();
      await expect.element(screen.getByTestId("host")).toBeEmptyDOMElement();
    },
  );
});
