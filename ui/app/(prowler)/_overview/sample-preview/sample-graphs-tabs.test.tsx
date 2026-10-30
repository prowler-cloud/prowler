import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SAMPLE_CHECKS } from "@/lib/sample-preview/sample-dataset";

import { SampleGraphsTabs } from "./sample-graphs-tabs";

const { fetchMock } = vi.hoisted(() => ({ fetchMock: vi.fn() }));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/",
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

describe("SampleGraphsTabs", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
  });

  it("shows the sample new failed findings in the default tab without fetching", () => {
    // Given
    const firstNewCheck = SAMPLE_CHECKS.find((check) => check.newFailed > 0)!;

    // When
    render(<SampleGraphsTabs />);

    // Then
    expect(
      screen.getByRole("tab", { name: "New Findings", selected: true }),
    ).toBeInTheDocument();
    expect(screen.getAllByText(firstNewCheck.title).length).toBeGreaterThan(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
