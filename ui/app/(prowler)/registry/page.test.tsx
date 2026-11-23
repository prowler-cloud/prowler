import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getRegistryBootstrap } from "@/actions/registry/registry";

import RegistryPage from "./page";

vi.mock("@/actions/registry/registry", () => ({
  getRegistryBootstrap: vi.fn(),
}));
vi.mock("@/lib/registry/presentation", () => ({
  readRegistryPresentation: () => ({}),
}));
vi.mock("@/components/shadcn/content-layout/content-layout", () => ({
  ContentLayout: ({ children }: { children: ReactNode }) => children,
}));
vi.mock("@/components/registry/registry-explorer", () => ({
  RegistryExplorer: () => <p>Registry catalog</p>,
}));
vi.mock("next/navigation", () => ({
  redirect: vi.fn((path: string) => {
    throw new Error(`redirect:${path}`);
  }),
}));

describe("Registry paid access", () => {
  beforeEach(() => vi.clearAllMocks());

  it("offers an upgrade on direct visits without loading the catalog", async () => {
    // Given
    vi.mocked(getRegistryBootstrap).mockResolvedValue({
      status: "subscription_required",
    });

    // When
    render(await RegistryPage());

    // Then
    expect(
      screen.getByRole("button", { name: "Unlock Registry" }),
    ).toBeVisible();
    expect(screen.queryByText("Registry catalog")).not.toBeInTheDocument();
  });

  it("keeps access denial separate from a paid plan upgrade", async () => {
    // Given
    vi.mocked(getRegistryBootstrap).mockResolvedValue({
      status: "access_denied",
    });

    // When / Then
    await expect(RegistryPage()).rejects.toThrow("redirect:/profile");
  });
});
