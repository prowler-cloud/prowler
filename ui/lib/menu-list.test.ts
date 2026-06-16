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

describe("getMenuList", () => {
  afterEach(() => {
    delete process.env.NEXT_PUBLIC_IS_CLOUD_ENV;
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

  it("should remove the new highlight from Attack Paths", () => {
    // Given / When
    const attackPaths = findMenu("Attack Paths");

    // Then
    expect(attackPaths).toEqual(
      expect.not.objectContaining({ highlight: true }),
    );
  });
});
