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
  isInstallable: false,
  notInstallableReason: "artifact_ships_with_prowler",
  isAdded: false,
  updateAvailable: false,
  extendsProviderSlugs: [],
};
const checksArtifact: RegistryMarketplaceArtifact = {
  ...artifact,
  normalizedName: "acme-aws-checks",
  name: "Acme AWS checks",
  isBuiltin: false,
  hasProvider: false,
  hasCompliance: false,
  isInstallable: true,
  notInstallableReason: undefined,
};

describe("Registry card install verdict", () => {
  it("offers Add for checks the API calls installable, though they define no provider", async () => {
    // Given
    const onAdd = vi.fn();
    const screen = await render(
      <RegistryArtifactCard
        artifact={checksArtifact}
        onAdd={onAdd}
        onRemove={vi.fn()}
      />,
    );

    // When
    await screen.getByRole("button", { name: "Add Acme AWS checks" }).click();

    // Then
    expect(onAdd).toHaveBeenCalledOnce();
  });

  it("says why an artifact cannot be installed instead of leaving a dead control", async () => {
    // Given / When
    const screen = await render(
      <RegistryArtifactCard
        artifact={{
          ...checksArtifact,
          isInstallable: false,
          notInstallableReason: "checks_target_is_not_builtin",
        }}
        onAdd={vi.fn()}
        onRemove={vi.fn()}
      />,
    );

    // Then
    await expect
      .element(
        screen.getByText(
          "Its checks are written for a provider this deployment does not ship.",
        ),
      )
      .toBeVisible();
    await expect
      .element(screen.getByRole("button", { name: /Add/ }))
      .not.toBeInTheDocument();
  });

  it("names the built-in providers whose scans an installed checks artifact changed", async () => {
    // Given / When
    const screen = await render(
      <RegistryArtifactCard
        artifact={{
          ...checksArtifact,
          isAdded: true,
          resolvedVersion: "0.2.2",
          extendsProviderSlugs: ["aws", "gcp"],
        }}
        onAdd={vi.fn()}
        onRemove={vi.fn()}
      />,
    );

    // Then
    await expect
      .element(
        screen.getByText("Adds checks to your AWS and Google Cloud scans."),
      )
      .toBeVisible();
  });
});

describe("Registry card metadata layout", () => {
  it("keeps Added when the installed version is unknown", async () => {
    // Given / When
    const screen = await render(
      <RegistryArtifactCard
        artifact={{ ...artifact, isBuiltin: false, isAdded: true }}
        onAdd={vi.fn()}
        onRemove={vi.fn()}
      />,
    );
    // Then
    await expect
      .element(screen.getByText("Added", { exact: true }))
      .toBeVisible();
    await expect
      .element(screen.getByText("Unknown", { exact: true }))
      .toBeVisible();
    await expect
      .element(screen.getByRole("button", { name: /Update/ }))
      .not.toBeInTheDocument();
  });
  it("offers Update with installed and available versions instead of Added", async () => {
    // Given
    const onAdd = vi.fn();
    const screen = await render(
      <RegistryArtifactCard
        artifact={{
          ...artifact,
          isBuiltin: false,
          isInstallable: true,
          isAdded: true,
          resolvedVersion: "1.0.0",
          updateAvailable: true,
        }}
        onAdd={onAdd}
        onRemove={vi.fn()}
      />,
    );
    // When
    await screen
      .getByRole("button", { name: "Update AWS security to 5.15.0" })
      .click();
    // Then
    expect(onAdd).toHaveBeenCalledOnce();
    await expect
      .element(screen.getByText("Added", { exact: true }))
      .not.toBeInTheDocument();
    await expect
      .element(screen.getByText("Installed", { exact: true }))
      .toBeVisible();
    await expect
      .element(screen.getByText("1.0.0", { exact: true }))
      .toBeVisible();
    await expect
      .element(screen.getByText("Available", { exact: true }))
      .toBeVisible();
  });

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
                  resolvedVersion: `${longVersion}-previous`,
                  isAdded: true,
                  updateAvailable: true,
                  checkCount: Number.MAX_SAFE_INTEGER,
                  complianceCount: 123456789,
                  totalDownloads: 9876543210,
                  isBuiltin: false,
                  isInstallable: true,
                  owners: [],
                }}
                onAdd={onAdd}
                onRemove={vi.fn()}
              />
            </li>
            <li>
              <RegistryTenantArtifactCard
                normalizedName="Catalog unavailable"
                resolvedVersion={longVersion}
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
      await screen
        .getByRole("button", { name: `Update Long metadata to ${longVersion}` })
        .click();
      expect(onAdd).toHaveBeenCalledOnce();
      await screen.getByRole("main").screenshot();
    },
  );
});
