import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

const { RealtimeDashboard } = vi.hoisted(() => ({
  RealtimeDashboard: vi.fn(() => null),
}));
vi.mock(
  "@/app/(prowler)/realtime/_components/dashboard/realtime-dashboard",
  () => ({ RealtimeDashboard }),
);
vi.mock(
  "@/app/(prowler)/realtime/_components/dashboard/realtime-dashboard-skeleton",
  () => ({ RealtimeDashboardSkeleton: () => null }),
);
vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: ({ children }: { children: React.ReactNode }) => (
    <>{children}</>
  ),
}));
vi.mock("@/components/shared/premium-preview-page", () => ({
  PremiumPreviewPage: () => <section data-testid="premium-preview" />,
}));

import RealtimePage from "./page";

describe("Realtime deployment availability", () => {
  it("renders the premium preview without the Realtime dashboard in Local Server", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    render(await RealtimePage({ searchParams: Promise.resolve({}) }));

    // Then
    expect(screen.getByTestId("premium-preview")).toBeInTheDocument();
    expect(RealtimeDashboard).not.toHaveBeenCalled();
  });
});
