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
  it("renders unchecked while the full catalog is shown", () => {
    render(<WatchlistFilterToggle />);

    expect(
      screen.getByRole("checkbox", { name: "Show only watchlist" }),
    ).not.toBeChecked();
  });

  it("turns the filter on when checked", async () => {
    const user = userEvent.setup();
    render(<WatchlistFilterToggle />);

    // When
    await user.click(
      screen.getByRole("checkbox", { name: "Show only watchlist" }),
    );

    // Then
    expect(useComplianceWatchlistViewStore.getState().showOnlyWatchlist).toBe(
      true,
    );
  });

  it("reflects a filter already turned on elsewhere", () => {
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: true });

    render(<WatchlistFilterToggle />);

    expect(
      screen.getByRole("checkbox", { name: "Show only watchlist" }),
    ).toBeChecked();
  });

  it("turns the filter back off when unchecked", async () => {
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: true });
    const user = userEvent.setup();
    render(<WatchlistFilterToggle />);

    // When
    await user.click(
      screen.getByRole("checkbox", { name: "Show only watchlist" }),
    );

    // Then
    expect(useComplianceWatchlistViewStore.getState().showOnlyWatchlist).toBe(
      false,
    );
  });
});
