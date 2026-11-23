import { afterEach, describe, expect, vi } from "vitest";
import { page } from "vitest/browser";

import { it } from "@/__tests__/fixtures";
import { render } from "@/__tests__/render-browser";
import { CloudUpgradeModal } from "@/components/shared/cloud-upgrade-modal";
import { useCloudUpgradeStore } from "@/store/cloud-upgrade/store";

import { RegistryUpgradePrompt } from "./registry-upgrade-prompt";

vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ permissions: { manage_billing: true } }),
}));

const VIEWPORTS = [
  { name: "mobile", width: 390, height: 844 },
  { name: "tablet", width: 768, height: 1024 },
  { name: "desktop", width: 1280, height: 800 },
];

describe("Registry paid plan prompt", () => {
  afterEach(() => {
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it.each(VIEWPORTS)(
    "opens the shared paid plan modal on $name",
    async ({ name, width, height }) => {
      // Given
      await page.viewport(width, height);
      const screen = await render(
        <main className="bg-bg-neutral-primary min-h-screen p-6">
          <RegistryUpgradePrompt />
          <CloudUpgradeModal />
        </main>,
      );

      // When
      await screen.getByRole("button", { name: "Unlock Registry" }).click();

      // Then
      await expect
        .element(page.getByRole("dialog", { name: "Unlock Prowler Registry" }))
        .toBeVisible();
      await expect
        .element(page.getByRole("link", { name: "Upgrade to Unlock Registry" }))
        .toHaveAttribute("href", "/billing?feature=registry");
      expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(width);
      await expect
        .poll(() =>
          page
            .getByRole("dialog", { name: "Unlock Prowler Registry" })
            .element()
            .getAnimations({ subtree: true })
            .every((animation) => animation.playState !== "running"),
        )
        .toBe(true);
      await page.screenshot({
        path: `../../tests/providers/evidence/registry-paywall-${name}.png`,
      });
    },
  );
});
