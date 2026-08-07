import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@sentry/nextjs", () => ({ getTraceData: () => ({}) }));
vi.mock("@/actions/providers", () => ({
  getProviders: vi.fn().mockResolvedValue({ data: [] }),
}));
vi.mock("@/actions/scans/scans", () => ({
  getScansByState: vi.fn().mockResolvedValue({ data: [] }),
}));
vi.mock("@/components/layout/authenticated-notice", () => ({
  AuthenticatedNoticeSlot: () => <div role="status">Account notice</div>,
}));
vi.mock("@/components/layout/main-layout/main-layout", () => ({
  default: ({
    authenticatedNoticeSlot,
    children,
  }: {
    authenticatedNoticeSlot?: ReactNode;
    children: ReactNode;
  }) => (
    <main>
      {authenticatedNoticeSlot}
      {children}
    </main>
  ),
}));
vi.mock("@/components/onboarding", () => ({
  OnboardingCheckpointWatcher: () => null,
  OnboardingGate: () => null,
  OnboardingSequenceBanner: () => null,
}));
vi.mock("@/components/runtime-config/runtime-public-config", () => ({
  RuntimePublicConfig: () => null,
}));
vi.mock("@/components/shadcn/navigation-progress", () => ({
  NavigationProgress: () => null,
}));
vi.mock("@/components/shadcn/toast", () => ({ Toaster: () => null }));
vi.mock("@/components/shared/task-polling-watcher", () => ({
  TaskPollingWatcher: () => null,
}));
vi.mock("@/components/side-panel", () => ({ GlobalSidePanel: () => null }));
vi.mock("@/components/survey/feedback-survey", () => ({
  FeedbackSurvey: () => null,
}));
vi.mock("@/config/fonts", () => ({
  fontMono: { variable: "font-mono" },
  fontSans: { variable: "font-sans" },
}));
vi.mock("@/config/site", () => ({
  siteConfig: { name: "Prowler", description: "Prowler" },
}));
vi.mock("@/lib/shared/env", () => ({ isCloud: () => false }));
vi.mock("@/lib/utils", () => ({
  cn: (...classes: string[]) => classes.join(" "),
}));
vi.mock("@/store/ui/store-initializer", () => ({
  StoreInitializer: () => null,
}));
vi.mock("../providers", () => ({
  Providers: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

import RootLayout from "./layout";

describe("authenticated layout", () => {
  it("composes the authenticated notice into the main layout", async () => {
    // Given / When
    render(await RootLayout({ children: <div>Page content</div> }));

    // Then
    expect(screen.getByRole("status")).toHaveTextContent("Account notice");
    expect(screen.getByText("Page content")).toBeVisible();
  });
});
