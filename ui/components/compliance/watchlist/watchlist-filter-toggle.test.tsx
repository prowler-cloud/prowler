import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

import { useComplianceWatchlistViewStore } from "@/store/compliance/store";

import { WatchlistFilterToggle } from "./watchlist-filter-toggle";

beforeEach(() => {
  localStorage.clear();
  useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: false });
});

describe("WatchlistFilterToggle", () => {
  it("updates the shared filter in both directions", async () => {
    // Given
    const user = userEvent.setup();
    render(<WatchlistFilterToggle />);
    const checkbox = screen.getByRole("checkbox", {
      name: "Show only watchlist",
    });

    // When
    await user.click(checkbox);

    // Then
    expect(useComplianceWatchlistViewStore.getState().showOnlyWatchlist).toBe(
      true,
    );

    // When
    await user.click(checkbox);

    // Then
    expect(useComplianceWatchlistViewStore.getState().showOnlyWatchlist).toBe(
      false,
    );
  });
});
