import { afterEach, describe, expect, it, vi } from "vitest";
import { page, userEvent } from "vitest/browser";

import { render } from "@/__tests__/render-browser";

import {
  RegistryArtifactCard,
  RegistryTenantArtifactCard,
} from "./registry-artifact-card";
import { RegistryArtifactGrid } from "./registry-artifact-grid";
import type { RegistryMarketplaceArtifact } from "./registry-explorer.model";

const artifact: RegistryMarketplaceArtifact = {
  normalizedName: "prowler-provider-aws",
  name: "AWS security",
  description: "Security checks and compliance frameworks for AWS resources.",
  latestVersion: "5.15.0",
  providers: ["aws"],
  isVerified: true,
  isOfficial: true,
  isBuiltin: true,
  isMeta: false,
  hasProvider: true,
  hasChecks: true,
  hasCompliance: true,
  checkCount: 645,
  complianceCount: 45,
  versionCount: 1,
  totalDownloads: 0,
  owners: [{ name: "Prowler", type: "organization" }],
  isAdded: false,
};

describe("Registry card metadata layout", () => {
  afterEach(async () => {
    localStorage.removeItem("theme");
    await page.viewport(1280, 800);
  });

  it("identifies each provider logo on hover and keyboard focus", async () => {
    // Given
    const screen = await render(
      <RegistryArtifactCard
        artifact={{ ...artifact, providers: ["aws", "gcp", "template"] }}
        onAdd={vi.fn()}
        onRemove={vi.fn()}
      />,
    );

    // When / Then: each visible provider uses its own display name.
    for (const name of ["AWS", "Google Cloud", "Template"]) {
      const logo = screen.getByRole("img", { name, exact: true });
      await logo.hover();
      await expect.element(screen.getByRole("tooltip")).toHaveTextContent(name);
      await userEvent.keyboard("{Escape}");
      await expect.element(screen.getByRole("tooltip")).not.toBeInTheDocument();
    }

    // When / Then: keyboard users can discover the same names.
    await userEvent.tab();
    await expect
      .element(screen.getByRole("img", { name: "AWS", exact: true }))
      .toHaveFocus();
    await expect.element(screen.getByRole("tooltip")).toHaveTextContent("AWS");
    await userEvent.tab();
    await expect
      .element(screen.getByRole("img", { name: "Google Cloud", exact: true }))
      .toHaveFocus();
    await expect
      .element(screen.getByRole("tooltip"))
      .toHaveTextContent("Google Cloud");
  });

  it.each([
    { width: 320, theme: "dark" },
    { width: 768, theme: "dark" },
    { width: 1440, theme: "dark" },
    { width: 320, theme: "light" },
    { width: 1440, theme: "light" },
  ])(
    "contains long metadata at $width px in $theme mode",
    async ({ width, theme }) => {
      // Given: the real grid includes normal, long, and catalog-less cards.
      await page.viewport(width, 1000);
      localStorage.setItem("theme", theme);
      const longVersion =
        "2026.123456789.123456789-preview.0123456789abcdef0123456789abcdef";
      const onAdd = vi.fn();
      const screen = await render(
        <main className="p-4">
          <RegistryArtifactGrid isEmpty={false} emptyMessage="No artifacts">
            <li>
              <RegistryArtifactCard
                artifact={artifact}
                onAdd={onAdd}
                onRemove={vi.fn()}
              />
            </li>
            <li>
              <RegistryArtifactCard
                artifact={{
                  ...artifact,
                  name: "Long metadata",
                  normalizedName: "long-metadata",
                  latestVersion: longVersion,
                  checkCount: Number.MAX_SAFE_INTEGER,
                  complianceCount: 123456789,
                  totalDownloads: 9876543210,
                  isBuiltin: false,
                  owners: [],
                }}
                onAdd={onAdd}
                onRemove={vi.fn()}
              />
            </li>
            <li>
              <RegistryTenantArtifactCard
                normalizedName="Catalog unavailable"
                versionSpec={longVersion}
                onRemove={vi.fn()}
              />
            </li>
          </RegistryArtifactGrid>
        </main>,
      );

      // Then: values stay complete, contained, and grouped in each card's footer.
      const metadataBlocks = screen.getByRole("group", {
        name: "Artifact metadata",
      });
      await expect.element(metadataBlocks.nth(2)).toBeVisible();
      await expect
        .element(
          metadataBlocks
            .nth(1)
            .getByText("9,007,199,254,740,991", { exact: true }),
        )
        .toBeVisible();
      await expect
        .element(
          metadataBlocks.nth(1).getByText("9,876,543,210", { exact: true }),
        )
        .toBeVisible();
      await expect
        .element(metadataBlocks.nth(2).getByText(longVersion, { exact: true }))
        .toBeVisible();
      for (const item of screen.getByRole("listitem").elements()) {
        const card = item.querySelector('[data-slot="card"]')!;
        const metadata = item.querySelector("dl")!;
        const bounds = card.getBoundingClientRect();
        expect(card.scrollWidth).toBeLessThanOrEqual(card.clientWidth);
        for (const value of Array.from(metadata.querySelectorAll("dt, dd"))) {
          expect(value.scrollWidth).toBeLessThanOrEqual(value.clientWidth);
          const range = document.createRange();
          range.selectNodeContents(value);
          for (const line of Array.from(range.getClientRects())) {
            expect(line.left).toBeGreaterThanOrEqual(bounds.left);
            expect(line.right).toBeLessThanOrEqual(bounds.right);
          }
        }
        const description = item.querySelector("p");
        expect(metadata.getBoundingClientRect().top).toBeGreaterThan(
          description!.getBoundingClientRect().bottom,
        );
      }
      expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(width);

      // When / Then: wrapping does not obstruct the card action.
      await screen.getByRole("button", { name: "Add Long metadata" }).click();
      expect(onAdd).toHaveBeenCalledOnce();
      await screen.getByRole("main").screenshot();
    },
  );
});
