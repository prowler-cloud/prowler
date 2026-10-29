import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { useFeatureFlagStateMock, notFound } = vi.hoisted(() => ({
  useFeatureFlagStateMock: vi.fn(),
  notFound: vi.fn(() => {
    throw new Error("NOT_FOUND");
  }),
}));

vi.mock("next/navigation", () => ({ notFound }));
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
    notFound.mockClear();
  });

  it("answers not found once the flag resolves off", () => {
    // Given
    useFeatureFlagStateMock.mockReturnValue(FEATURE_FLAG_STATE.OFF);
    vi.spyOn(console, "error").mockImplementation(() => {});

    // When / Then
    expect(renderRoute).toThrow("NOT_FOUND");
    expect(notFound).toHaveBeenCalled();
  });

  it("renders the route once the flag resolves on", () => {
    // Given
    useFeatureFlagStateMock.mockReturnValue(FEATURE_FLAG_STATE.ON);

    // When
    renderRoute();

    // Then
    expect(screen.getByText("route content")).toBeInTheDocument();
    expect(notFound).not.toHaveBeenCalled();
  });

  it("renders nothing while the flag is unresolved", () => {
    // Given
    useFeatureFlagStateMock.mockReturnValue(FEATURE_FLAG_STATE.PENDING);

    // When
    const { container } = renderRoute();

    // Then
    expect(container).toBeEmptyDOMElement();
    expect(notFound).not.toHaveBeenCalled();
  });
});
