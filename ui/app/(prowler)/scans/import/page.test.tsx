import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({
  redirect: vi.fn(),
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: () => true,
}));

vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: ({ children }: { children: ReactNode }) => (
    <main>{children}</main>
  ),
}));

import CliImportPage from "./page";

describe("CliImportPage", () => {
  it("should expose the CLI commands through the shared copy control", () => {
    // Given / When
    render(<CliImportPage />);

    // Then
    expect(
      screen.getByRole("button", { name: "Copy CLI commands" }),
    ).toBeInTheDocument();
  });
});
