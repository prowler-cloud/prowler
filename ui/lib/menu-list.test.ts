import { afterEach, describe, expect, it } from "vitest";

import { getMenuList } from "./menu-list";

const findMenu = (label: string) =>
  getMenuList({ pathname: "/alerts" })
    .flatMap((group) => group.menus)
    .find((menu) => menu.label === label);

const findSubmenu = (label: string) =>
  getMenuList({ pathname: "/alerts" })
    .flatMap((group) => group.menus)
    .flatMap((menu) => menu.submenus ?? [])
    .find((submenu) => submenu.label === label);

const findApiReference = (options: Parameters<typeof getMenuList>[0]) =>
  getMenuList(options)
    .flatMap((group) => group.menus)
    .flatMap((menu) => menu.submenus ?? [])
    .find((submenu) => submenu.label === "API reference");

const getTopLevelLabels = () =>
  getMenuList({ pathname: "/", apiDocsUrl: null }).flatMap((group) =>
    group.menus.map((menu) => menu.label),
  );

const getConfigurationLabels = () =>
  getMenuList({ pathname: "/lighthouse/settings", apiDocsUrl: null })
    .flatMap((group) => group.menus)
    .find((menu) => menu.label === "Configuration")
    ?.submenus?.map((submenu) => submenu.label) ?? [];

const getConfigurationSubmenu = (label: string) =>
  getMenuList({ pathname: "/lighthouse/settings", apiDocsUrl: null })
    .flatMap((group) => group.menus)
    .flatMap((menu) => menu.submenus ?? [])
    .find((submenu) => submenu.label === label);

describe("getMenuList", () => {
  afterEach(() => {
    delete process.env.NEXT_PUBLIC_IS_CLOUD_ENV;
  });

  describe("API reference link", () => {
    it("should use the apiDocsUrl provided by the caller in OSS", () => {
      // Given / When — the caller resolves the runtime value (hydration-safe)
      const apiRef = findApiReference({
        pathname: "/",
        apiDocsUrl: "https://self-hosted.example/api/v1/docs",
      });

      // Then
      expect(apiRef?.href).toBe("https://self-hosted.example/api/v1/docs");
    });

    it("should default to an empty href when no apiDocsUrl is provided", () => {
      // Given / When — no island read here, so SSR and client agree
      const apiRef = findApiReference({ pathname: "/" });

      // Then
      expect(apiRef?.href).toBe("");
    });

    it("should use the Cloud docs URL and ignore apiDocsUrl when Cloud is enabled", () => {
      // Given
      process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "true";

      // When
      const apiRef = findApiReference({
        pathname: "/",
        apiDocsUrl: "https://ignored.example/docs",
      });

      // Then
      expect(apiRef?.href).toBe("https://api.prowler.com/api/v1/docs");
    });
  });

  it("should show Alerts as disabled Cloud-only in OSS when Cloud is disabled", () => {
    // Given / When
    const alerts = findSubmenu("Alerts");

    // Then
    expect(alerts).toEqual(
      expect.objectContaining({
        href: "/alerts",
        disabled: true,
        cloudOnly: true,
        highlight: true,
        active: false,
      }),
    );
  });

  it("should show Alerts as new under Configuration when Cloud is enabled", () => {
    // Given
    process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "true";

    // When
    const alerts = findSubmenu("Alerts");

    // Then
    expect(alerts).toEqual(
      expect.objectContaining({
        href: "/alerts",
        active: true,
        highlight: true,
      }),
    );
  });

  it("should show Scan as disabled Cloud-only in OSS when Cloud is disabled", () => {
    // Given / When
    const scanConfig = findSubmenu("Scan");

    // Then
    expect(scanConfig).toEqual(
      expect.objectContaining({
        href: "/scans/config",
        disabled: true,
        cloudOnly: true,
        highlight: true,
        active: false,
      }),
    );
  });

  it("should show Scan as new under Configuration when Cloud is enabled", () => {
    // Given
    process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "true";

    // When
    const menus = getMenuList({ pathname: "/scans/config" }).flatMap(
      (group) => group.menus,
    );
    const scanConfig = menus
      .flatMap((menu) => menu.submenus ?? [])
      .find((submenu) => submenu.label === "Scan");
    const scans = menus.find((menu) => menu.label === "Scans");

    // Then
    expect(scanConfig).toEqual(
      expect.objectContaining({
        href: "/scans/config",
        active: true,
        highlight: true,
      }),
    );
    // The top-level Scans item uses an exact-match active rule, so it must stay
    // inactive on the `/scans/config` sub-route.
    expect(scans).toEqual(expect.objectContaining({ active: false }));
  });

  it("should remove the new highlight from Attack Paths", () => {
    // Given / When
    const attackPaths = findMenu("Attack Paths");

    // Then
    expect(attackPaths).toEqual(
      expect.not.objectContaining({ highlight: true }),
    );
  });

  it("should keep Lighthouse as a browse item in OSS", () => {
    // Given / When
    const labels = getTopLevelLabels();

    // Then
    expect(labels).toContain("Lighthouse AI");
  });

  it("should move Lighthouse out of the Cloud browse menu but keep its configuration entry", () => {
    // Given
    process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "true";

    // When
    const labels = getTopLevelLabels();
    const configLabels = getConfigurationLabels();
    const lighthouseSettings = getConfigurationSubmenu("Lighthouse AI");

    // Then
    expect(labels).not.toContain("Lighthouse AI");
    expect(configLabels).toContain("Lighthouse AI");
    expect(lighthouseSettings?.href).toBe("/lighthouse/settings");
  });
});
