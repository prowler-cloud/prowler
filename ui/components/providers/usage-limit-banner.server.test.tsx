import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { shouldDisplayUsageLimitBannerMock, usageLimitBannerSpy } = vi.hoisted(
  () => ({
    shouldDisplayUsageLimitBannerMock: vi.fn(),
    usageLimitBannerSpy: vi.fn(),
  }),
);

vi.mock("./usage-limit-banner.resolver", () => ({
  shouldDisplayUsageLimitBanner: shouldDisplayUsageLimitBannerMock,
}));

vi.mock("./usage-limit-banner", () => ({
  UsageLimitBanner: (props: unknown) => {
    usageLimitBannerSpy(props);
    return <div role="alert">Usage limit exceeded</div>;
  },
}));

import { UsageLimitBannerSSR } from "./usage-limit-banner.server";

describe("UsageLimitBannerSSR", () => {
  beforeEach(() => {
    shouldDisplayUsageLimitBannerMock.mockReset();
    usageLimitBannerSpy.mockReset();
  });

  it("renders the existing banner when the neutral resolver returns true", async () => {
    // Given
    shouldDisplayUsageLimitBannerMock.mockResolvedValue(true);

    // When
    render(
      await UsageLimitBannerSSR({
        allowHide: true,
        showBillingButton: false,
        className: "m-4",
      }),
    );

    // Then
    expect(screen.getByRole("alert")).toBeVisible();
    expect(screen.getByRole("alert").parentElement).toHaveClass("m-4");
    expect(usageLimitBannerSpy).toHaveBeenCalledWith({
      allowHide: true,
      showBillingButton: false,
    });
  });

  it("renders nothing when the neutral resolver returns false", async () => {
    // Given
    shouldDisplayUsageLimitBannerMock.mockResolvedValue(false);

    // When
    const { container } = render(await UsageLimitBannerSSR({}));

    // Then
    expect(container).toBeEmptyDOMElement();
    expect(usageLimitBannerSpy).not.toHaveBeenCalled();
  });
});
