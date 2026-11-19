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
          notInstallableReason: "artifact_targets_no_provider",
        }}
        onAdd={vi.fn()}
        onRemove={vi.fn()}
      />,
    );

    // Then
    await expect
      .element(
        screen.getByText("It ships checks but names no provider to extend."),
      )
      .toBeVisible();
    await expect
      .element(screen.getByRole("button", { name: /Add/ }))
      .not.toBeInTheDocument();
  });

  it("links an artifact that needs approved access to its Registry bundle", async () => {
    // Given / When
    const screen = await render(
      <RegistryArtifactCard
        artifact={{
          ...checksArtifact,
          isInstallable: false,
          notInstallableReason: "access_required",
          accessRequestPath: "/bundles/vcf-bundle",
        }}
        onAdd={vi.fn()}
        onRemove={vi.fn()}
        registryUrl="https://registry.example.com/"
      />,
    );

    // Then: the link takes the action slot and the note says why.
    const link = screen.getByRole("link", {
      name: "Request access to Acme AWS checks in the Prowler Registry (opens in a new tab)",
    });
    await expect
      .element(link)
      .toHaveAttribute(
        "href",
        "https://registry.example.com/bundles/vcf-bundle",
      );
    await expect.element(link).toHaveTextContent("Request access");
    await expect
      .element(
        screen.getByText(
          "Needs approved access in the Prowler Registry. Once approved, it installs with that account's Registry API key.",
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

describe("Registry tenant card", () => {
  it("still names the extended providers when the catalog no longer lists the artifact", async () => {
    // Given / When
    const screen = await render(
      <RegistryTenantArtifactCard
        extendsProviderSlugs={["aws"]}
        normalizedName="retired-aws-checks"
        onRemove={vi.fn()}
        resolvedVersion="0.2.2"
      />,
    );

    // Then
    await expect
      .element(screen.getByText("Adds checks to your AWS scans."))
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
    const metadata = screen.getByRole("group", { name: "Artifact metadata" });
    await expect
      .element(metadata.getByText("Installed", { exact: true }))
      .toBeInTheDocument();
    await expect
      .element(metadata.getByText("Available", { exact: true }))
      .toBeInTheDocument();
    // Installed → available, read in that order.
    expect(metadata.element().firstElementChild?.textContent).toBe(
      "Installed1.0.0Available→ 5.15.0",
    );
  });

  afterEach(async () => {
    localStorage.removeItem("theme");
    await page.viewport(1280, 800);
  });

  it("identifies each provider logo on hover and keyboard focus", async () => {
    // Given
    const screen = await render(
      <RegistryArtifactCard
        artifact={{ ...artifact, providers: ["aws", "gcp"] }}
        onAdd={vi.fn()}
        onRemove={vi.fn()}
      />,
    );

    // When / Then: each visible provider uses its own display name.
    for (const name of ["AWS", "Google Cloud"]) {
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

  it("names Registry providers in text, since they have no logo of their own", async () => {
    // Given: an artifact covering a built-in and two providers without a logo
    const screen = await render(
      <RegistryArtifactCard
        artifact={{
          ...artifact,
          providers: ["aws", "template", "local-template"],
        }}
        onAdd={vi.fn()}
        onRemove={vi.fn()}
      />,
    );

    // Then: the built-in keeps its logo, the others read without hovering
    await expect
      .element(screen.getByRole("img", { name: "AWS", exact: true }))
      .toBeVisible();
    for (const name of ["Template", "Local Template"]) {
      await expect
        .element(screen.getByText(name, { exact: true }))
        .toBeVisible();
    }
  });

  it("shows three Registry provider names and lists the rest behind +N", async () => {
    // Given: a built-in and six providers without a logo
    const screen = await render(
      <RegistryArtifactCard
        artifact={{
          ...artifact,
          providers: [
            "aws",
            "openai",
            "chatgpt",
            "vcf",
            "snowflake",
            "datadog",
            "salesforce",
          ],
        }}
        onAdd={vi.fn()}
        onRemove={vi.fn()}
      />,
    );

    // Then: three names read as text and one +3 holds the rest
    const names = screen.getByRole("list", { name: "Providers" });
    expect(
      names
        .getByRole("listitem")
        .elements()
        .map((item) => item.textContent),
    ).toEqual(["Openai", "Chatgpt", "Vcf", "+3"]);

    // When: keyboard users reach the overflow
    const more = screen.getByRole("img", {
      name: "3 more: Snowflake, Datadog, Salesforce",
    });
    (more.element() as HTMLElement).focus();

    // Then
    await expect
      .element(screen.getByRole("tooltip"))
      .toHaveTextContent("Snowflake, Datadog, Salesforce");
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
          <RegistryArtifactGrid>
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

      // Then: values stay complete and inside each card.
      const contents = screen.getByRole("list", { name: "Contents" });
      const metadataBlocks = screen.getByRole("group", {
        name: "Artifact metadata",
      });
      await expect.element(metadataBlocks.nth(2)).toBeVisible();
      await expect
        .element(
          contents.nth(1).getByText("9,007,199,254,740,991", { exact: true }),
        )
        .toBeVisible();
      await expect
        .element(contents.nth(1).getByText("123,456,789", { exact: true }))
        .toBeVisible();
      await expect
        .element(
          metadataBlocks.nth(1).getByText("9,876,543,210", { exact: true }),
        )
        .toBeVisible();
      await expect
        .element(metadataBlocks.nth(2).getByText(longVersion, { exact: true }))
        .toBeVisible();
      const cards = Array.from(document.querySelectorAll('[data-slot="card"]'));
      expect(cards).toHaveLength(3);
      for (const card of cards) {
        const bounds = card.getBoundingClientRect();
        expect(card.scrollWidth).toBeLessThanOrEqual(card.clientWidth);
        const values = card.querySelectorAll(
          'ul[aria-label="Contents"] > li, dl dd',
        );
        for (const value of Array.from(values)) {
          expect(value.scrollWidth).toBeLessThanOrEqual(value.clientWidth);
          const range = document.createRange();
          range.selectNodeContents(value);
          for (const line of Array.from(range.getClientRects())) {
            expect(line.left).toBeGreaterThanOrEqual(bounds.left);
            expect(line.right).toBeLessThanOrEqual(bounds.right);
          }
        }
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

  it("lines up the footers of cards in the same row", async () => {
    // Given: three cards with different descriptions, chips, notes and
    // providers, most of them Registry-only.
    await page.viewport(1440, 1000);
    await render(
      <main className="p-4">
        <RegistryArtifactGrid>
          <li>
            <RegistryArtifactCard
              artifact={artifact}
              onAdd={vi.fn()}
              onRemove={vi.fn()}
            />
          </li>
          <li>
            <RegistryArtifactCard
              artifact={{
                ...checksArtifact,
                providers: [
                  "aws",
                  "azure",
                  "openai",
                  "chatgpt",
                  "vcf",
                  "snowflake",
                  "datadog",
                  "salesforce",
                ],
                description: undefined,
                isInstallable: false,
                notInstallableReason: "checks_target_is_not_builtin",
              }}
              onAdd={vi.fn()}
              onRemove={vi.fn()}
            />
          </li>
          <li>
            <RegistryTenantArtifactCard
              normalizedName="retired-aws-checks"
              resolvedVersion="0.2.2"
              onRemove={vi.fn()}
            />
          </li>
        </RegistryArtifactGrid>
      </main>,
    );

    // Then
    const footerTops = Array.from(
      document.querySelectorAll('dl[aria-label="Artifact metadata"]'),
      (metadata) =>
        Math.round(metadata.parentElement!.getBoundingClientRect().top),
    );
    expect(footerTops).toHaveLength(3);
    expect(new Set(footerTops).size).toBe(1);
  });
});
