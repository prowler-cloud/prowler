import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

const { isCloudMock } = vi.hoisted(() => ({
  isCloudMock: vi.fn(),
}));

vi.mock("@/components/shadcn/skeleton/skeleton", () => ({
  Skeleton: () => <span />,
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: isCloudMock,
}));

import { SkeletonTableUser } from "./skeleton-table-user";

const getColumnCounts = (container: HTMLElement) => ({
  header: container.querySelectorAll("thead th").length,
  row: container.querySelector("tbody tr")?.querySelectorAll("td").length,
});

describe("SkeletonTableUser", () => {
  it("should render seven columns in Cloud", () => {
    // Given
    isCloudMock.mockReturnValue(true);

    // When
    const { container } = render(<SkeletonTableUser />);

    // Then
    expect(getColumnCounts(container)).toEqual({ header: 7, row: 7 });
  });

  it("should render six columns in OSS", () => {
    // Given
    isCloudMock.mockReturnValue(false);

    // When
    const { container } = render(<SkeletonTableUser />);

    // Then
    expect(getColumnCounts(container)).toEqual({ header: 6, row: 6 });
  });
});
