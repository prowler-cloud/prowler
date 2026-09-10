import { afterEach, describe, expect, it, vi } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import type { RolePermissionAttributes } from "@/types/users";

import {
  filterNavigationByPermissions,
  getNavigationConfig,
} from "./navigation-config";
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
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

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
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    const children = getConfigurationChildren();

    // Then
    expect(children.map((item) => item.label)).toEqual([
      "Providers",
      "Alerts",
      "Mutelist",
      "Scans",
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
    expect(children.find((item) => item.label === "Scans")).toEqual(
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
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

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
      configuration.children.find((item) => item.label === "Scans"),
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

  it("keeps the Cloud Billing destination for users with billing permission", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const permissions = {
      manage_billing: true,
    } as RolePermissionAttributes;

    // When
    const billing = getNavigationConfig({
      pathname: "/billing",
      apiDocsUrl: null,
      cloudBillingEnabled: true,
      permissions,
    })
      .flatMap((section) => section.items)
      .find((item) => item.label === "Billing");

    // Then
    expect(billing).toEqual(
      expect.objectContaining({
        href: "/billing",
        active: true,
        requiredPermission: "manage_billing",
      }),
    );
  });

  it("hides Billing without permission and in Local Server", () => {
    // Given
    const permissions = {
      manage_billing: false,
    } as RolePermissionAttributes;
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

    // When
    const cloudItems = getNavigationConfig({
      pathname: "/",
      apiDocsUrl: null,
      cloudBillingEnabled: true,
      permissions,
    }).flatMap((section) => section.items);
    const enterpriseItems = getNavigationConfig({
      pathname: "/",
      apiDocsUrl: null,
      cloudBillingEnabled: false,
      permissions: { ...permissions, manage_billing: true },
    }).flatMap((section) => section.items);
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    const localItems = getNavigationConfig({
      pathname: "/",
      apiDocsUrl: null,
      cloudBillingEnabled: true,
      permissions: { ...permissions, manage_billing: true },
    }).flatMap((section) => section.items);

    // Then
    expect(cloudItems.find((item) => item.label === "Billing")).toBeUndefined();
    expect(
      enterpriseItems.find((item) => item.label === "Billing"),
    ).toBeUndefined();
    expect(localItems.find((item) => item.label === "Billing")).toBeUndefined();
  });

  it("keeps environment-specific API documentation destinations", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    const localApiReference = getNavigationConfig({
      pathname: "/",
      apiDocsUrl: "https://local.example/api/v1/docs",
    })
      .flatMap((section) => section.items)
      .find((item) => item.label === "API Reference");

    vi.stubEnv("UI_CLOUD_ENABLED", "true");
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

  it("omits the Local Server API reference when no URL is configured", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    const items = getNavigationConfig({
      pathname: "/",
      apiDocsUrl: null,
    }).flatMap((section) => section.items);

    // Then
    expect(
      items.find((item) => item.label === "API Reference"),
    ).toBeUndefined();
  });

  it("filters navigation by required permission after visible copy changes", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const sections = getNavigationConfig({
      pathname: "/integrations",
      apiDocsUrl: null,
    }).map((section) => ({
      ...section,
      items: section.items.map((item) =>
        item.kind === NAVIGATION_ITEM_KIND.COLLAPSIBLE
          ? {
              ...item,
              children: item.children.map((child) =>
                child.label === "Integrations"
                  ? { ...child, label: "Connected apps" }
                  : child,
              ),
            }
          : item,
      ),
    }));
    const permissions = {
      manage_integrations: false,
    } as RolePermissionAttributes;

    // When
    const filtered = filterNavigationByPermissions(sections, permissions);

    // Then
    expect(
      filtered
        .flatMap((section) => section.items)
        .filter((item) => item.kind === NAVIGATION_ITEM_KIND.COLLAPSIBLE)
        .flatMap((item) => item.children)
        .find((item) => item.label === "Connected apps"),
    ).toBeUndefined();
  });

  it("keeps navigation when the required permission is granted", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const permissions = {
      manage_integrations: true,
    } as RolePermissionAttributes;

    // When
    const configuration = getNavigationConfig({
      pathname: "/integrations",
      apiDocsUrl: null,
      permissions,
    })
      .flatMap((section) => section.items)
      .find((item) => item.label === "Configuration");

    // Then
    expect(configuration).toEqual(
      expect.objectContaining({
        children: expect.arrayContaining([
          expect.objectContaining({ label: "Integrations" }),
        ]),
      }),
    );
  });

  it("matches complete route segments without stealing nested settings routes", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

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
