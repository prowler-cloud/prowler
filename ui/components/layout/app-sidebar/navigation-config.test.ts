import { afterEach, describe, expect, it, vi } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { getNavigationConfig } from "./navigation-config";
import { NAVIGATION_ITEM_KIND } from "./types";

const getItem = (label: string) =>
  getNavigationConfig({ pathname: "/alerts", apiDocsUrl: null })
    .flatMap((section) => section.items)
    .find((item) => item.label === label);

const getConfigurationChildren = () => {
  const configuration = getItem("Configuration");

  if (configuration?.kind !== NAVIGATION_ITEM_KIND.COLLAPSIBLE) {
    throw new Error("Configuration must be a collapsible navigation item");
  }

  return configuration.children;
};

describe("getNavigationConfig", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("groups the Local Server navigation without losing available features", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    const sections = getNavigationConfig({
      pathname: "/",
      apiDocsUrl: "https://local.example/api/v1/docs",
    });

    // Then
    expect(sections.map((section) => section.label ?? null)).toEqual([
      null,
      "SECURITY",
      "SETTINGS",
      "HELP",
    ]);
    expect(sections[0]?.items.map((item) => item.label)).toEqual([
      "Overview",
      "Lighthouse AI",
    ]);
    expect(sections[1]?.items.map((item) => item.label)).toEqual([
      "Compliance",
      "Findings",
      "Attack Paths",
      "Scans",
      "Resources",
    ]);
    expect(sections[2]?.items.map((item) => item.label)).toEqual([
      "Configuration",
      "Organization",
    ]);
    expect(sections[3]?.items.map((item) => item.label)).toEqual([
      "Documentation",
      "API Reference",
      "Community Support",
      "Prowler Hub",
    ]);
  });

  it("models Local Server Cloud features as contextual upgrade actions", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    const children = getConfigurationChildren();

    // Then
    expect(children.map((item) => item.label)).toEqual([
      "Providers",
      "Alerts",
      "Mutelist",
      "Scan Settings",
      "CLI Import",
      "Integrations",
      "Lighthouse AI",
    ]);
    expect(children.find((item) => item.label === "Alerts")).toEqual(
      expect.objectContaining({
        kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE,
        cloudUpgradeFeature: CLOUD_UPGRADE_FEATURE.ALERTS,
      }),
    );
    expect(children.find((item) => item.label === "Scan Settings")).toEqual(
      expect.objectContaining({
        kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE,
        cloudUpgradeFeature: CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION,
      }),
    );
    expect(children.find((item) => item.label === "CLI Import")).toEqual(
      expect.objectContaining({
        kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE,
        cloudUpgradeFeature: CLOUD_UPGRADE_FEATURE.CLI_IMPORT,
      }),
    );
  });

  it("uses Cloud destinations and current New badges", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    const sections = getNavigationConfig({
      pathname: "/scans/config",
      apiDocsUrl: "https://ignored.example/docs",
    });
    const items = sections.flatMap((section) => section.items);
    const configuration = items.find((item) => item.label === "Configuration");

    if (configuration?.kind !== NAVIGATION_ITEM_KIND.COLLAPSIBLE) {
      throw new Error("Configuration must be a collapsible navigation item");
    }

    // Then
    expect(sections[0]?.items.map((item) => item.label)).toEqual(["Overview"]);
    expect(configuration.children).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: "CLI Import" }),
      ]),
    );
    expect(
      configuration.children.find((item) => item.label === "Alerts"),
    ).toEqual(expect.objectContaining({ highlight: true }));
    expect(
      configuration.children.find((item) => item.label === "Scan Settings"),
    ).toEqual(expect.objectContaining({ active: true, highlight: true }));
    expect(items.find((item) => item.label === "Attack Paths")).not.toEqual(
      expect.objectContaining({ highlight: true }),
    );
    expect(sections[3]?.items.map((item) => item.label)).toEqual([
      "Documentation",
      "API Reference",
      "Support Desk",
      "Prowler Hub",
    ]);
  });

  it("keeps environment-specific API documentation destinations", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    const localApiReference = getNavigationConfig({
      pathname: "/",
      apiDocsUrl: "https://local.example/api/v1/docs",
    })
      .flatMap((section) => section.items)
      .find((item) => item.label === "API Reference");

    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
    const cloudApiReference = getNavigationConfig({
      pathname: "/",
      apiDocsUrl: "https://ignored.example/docs",
    })
      .flatMap((section) => section.items)
      .find((item) => item.label === "API Reference");

    // Then
    expect(localApiReference).toEqual(
      expect.objectContaining({ href: "https://local.example/api/v1/docs" }),
    );
    expect(cloudApiReference).toEqual(
      expect.objectContaining({ href: "https://api.prowler.com/api/v1/docs" }),
    );
  });

  it("matches complete route segments without stealing nested settings routes", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    const scanDetails = getNavigationConfig({
      pathname: "/scans/scan-123",
      apiDocsUrl: null,
    });
    const scanSettings = getNavigationConfig({
      pathname: "/scans/config/edit",
      apiDocsUrl: null,
    });

    // Then
    expect(
      scanDetails
        .flatMap((section) => section.items)
        .find((item) => item.label === "Scans"),
    ).toEqual(expect.objectContaining({ active: true }));
    expect(
      scanSettings
        .flatMap((section) => section.items)
        .find((item) => item.label === "Scans"),
    ).toEqual(expect.objectContaining({ active: false }));
  });
});
