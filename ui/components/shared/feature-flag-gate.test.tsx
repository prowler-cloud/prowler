import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { useFeatureFlagStateMock } = vi.hoisted(() => ({
  useFeatureFlagStateMock: vi.fn(),
}));

vi.mock("@/lib/feature-flags", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/feature-flags")>()),
  useFeatureFlagState: useFeatureFlagStateMock,
}));

import { FEATURE_FLAG, FEATURE_FLAG_STATE } from "@/lib/feature-flags";

import { FeatureFlagGate } from "./feature-flag-gate";

const renderGate = () =>
  render(
    <FeatureFlagGate
      flag={FEATURE_FLAG.ISSUES}
      fallback={<p>off state</p>}
      pending={<p>pending state</p>}
    >
      <p>on state</p>
    </FeatureFlagGate>,
  );

describe("FeatureFlagGate", () => {
  beforeEach(() => {
    useFeatureFlagStateMock.mockReset();
  });

  it("should ask for the given flag", () => {
    useFeatureFlagStateMock.mockReturnValue(FEATURE_FLAG_STATE.OFF);

    renderGate();

    expect(useFeatureFlagStateMock).toHaveBeenCalledWith("issues-feature");
  });

  it("should render the children when the flag is on", () => {
    useFeatureFlagStateMock.mockReturnValue(FEATURE_FLAG_STATE.ON);

    renderGate();

    expect(screen.getByText("on state")).toBeInTheDocument();
    expect(screen.queryByText("off state")).not.toBeInTheDocument();
    expect(screen.queryByText("pending state")).not.toBeInTheDocument();
  });

  it("should render the fallback when the flag is off", () => {
    useFeatureFlagStateMock.mockReturnValue(FEATURE_FLAG_STATE.OFF);

    renderGate();

    expect(screen.getByText("off state")).toBeInTheDocument();
    expect(screen.queryByText("on state")).not.toBeInTheDocument();
  });

  it("should render the pending slot while the flag is unresolved", () => {
    useFeatureFlagStateMock.mockReturnValue(FEATURE_FLAG_STATE.PENDING);

    renderGate();

    expect(screen.getByText("pending state")).toBeInTheDocument();
    expect(screen.queryByText("on state")).not.toBeInTheDocument();
    expect(screen.queryByText("off state")).not.toBeInTheDocument();
  });

  it.each([
    ["off", FEATURE_FLAG_STATE.OFF],
    ["pending", FEATURE_FLAG_STATE.PENDING],
  ])(
    "should render nothing by default when the flag is %s",
    (_label, state) => {
      useFeatureFlagStateMock.mockReturnValue(state);

      const { container } = render(
        <FeatureFlagGate flag={FEATURE_FLAG.ISSUES}>
          <p>on state</p>
        </FeatureFlagGate>,
      );

      expect(container).toBeEmptyDOMElement();
    },
  );
});
