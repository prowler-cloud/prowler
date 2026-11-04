import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { useFeatureFlagStateMock, redirect } = vi.hoisted(() => ({
  useFeatureFlagStateMock: vi.fn(),
  redirect: vi.fn(() => {
    throw new Error("REDIRECT");
  }),
}));

vi.mock("next/navigation", () => ({ redirect }));
vi.mock("@/lib/feature-flags", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/feature-flags")>()),
  useFeatureFlagState: useFeatureFlagStateMock,
}));

import { FEATURE_FLAG, FEATURE_FLAG_STATE } from "@/lib/feature-flags";

import { FeatureFlagRoute } from "./feature-flag-route";

const renderRoute = () =>
  render(
    <FeatureFlagRoute flag={FEATURE_FLAG.ISSUES}>
      <p>route content</p>
    </FeatureFlagRoute>,
  );

describe("FeatureFlagRoute", () => {
  beforeEach(() => {
    useFeatureFlagStateMock.mockReset();
    redirect.mockClear();
  });

  it("sends the user to the overview once the flag resolves off", () => {
    // Given
    useFeatureFlagStateMock.mockReturnValue(FEATURE_FLAG_STATE.OFF);
    vi.spyOn(console, "error").mockImplementation(() => {});

    // When / Then
    expect(renderRoute).toThrow("REDIRECT");
    expect(redirect).toHaveBeenCalledWith("/");
  });

  it("renders the route once the flag resolves on", () => {
    // Given
    useFeatureFlagStateMock.mockReturnValue(FEATURE_FLAG_STATE.ON);

    // When
    renderRoute();

    // Then
    expect(screen.getByText("route content")).toBeInTheDocument();
    expect(redirect).not.toHaveBeenCalled();
  });

  it("renders nothing while the flag is unresolved", () => {
    // Given
    useFeatureFlagStateMock.mockReturnValue(FEATURE_FLAG_STATE.PENDING);

    // When
    const { container } = renderRoute();

    // Then
    expect(container).toBeEmptyDOMElement();
    expect(redirect).not.toHaveBeenCalled();
  });
});
