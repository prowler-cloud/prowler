import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { usePageReadyStore } from "@/store/page-ready";

import { PageReady } from "../page-ready";

vi.mock("next/navigation", () => ({
  usePathname: () => "/compliance",
}));

describe("PageReady", () => {
  beforeEach(() => usePageReadyStore.setState({ readyPath: null }));

  it("marks the current route ready on mount", () => {
    render(<PageReady />);
    expect(usePageReadyStore.getState().readyPath).toBe("/compliance");
  });

  it("clears readiness on unmount", () => {
    const { unmount } = render(<PageReady />);
    unmount();
    expect(usePageReadyStore.getState().readyPath).toBeNull();
  });

  it("renders nothing", () => {
    const { container } = render(<PageReady />);
    expect(container).toBeEmptyDOMElement();
  });
});
