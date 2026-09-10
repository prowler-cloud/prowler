import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  CrossAccountOverviewSkeleton,
  CrossProviderOverviewSkeleton,
} from "./multiple-scans-skeleton";

describe("Multiple Scans skeletons", () => {
  it("mirrors the cross-provider overview layout", () => {
    // Given / When
    render(<CrossProviderOverviewSkeleton />);

    // Then
    const loadingState = screen.getByRole("status", {
      name: "Loading across provider types",
    });
    expect(
      within(loadingState).getByRole("heading", {
        name: "Across provider types",
      }),
    ).toBeInTheDocument();
    expect(
      loadingState.querySelectorAll('[data-skeleton-kind="filter"]'),
    ).toHaveLength(3);
    expect(
      loadingState.querySelectorAll('[data-skeleton-kind="framework-card"]'),
    ).toHaveLength(3);
  });

  it("mirrors the cross-account provider groups", () => {
    // Given / When
    render(<CrossAccountOverviewSkeleton />);

    // Then
    const loadingState = screen.getByRole("status", {
      name: "Loading across providers",
    });
    expect(
      within(loadingState).getByRole("heading", {
        name: "Across providers",
      }),
    ).toBeInTheDocument();
    expect(within(loadingState).getAllByRole("button")).toHaveLength(2);
  });
});
