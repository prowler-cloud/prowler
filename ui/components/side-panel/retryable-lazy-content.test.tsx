import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { RetryableLazyContent } from "./retryable-lazy-content";

describe("RetryableLazyContent", () => {
  it("loads the lazy chunk again after the first import rejects", async () => {
    // Given
    const user = userEvent.setup();
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    const load = vi
      .fn()
      .mockRejectedValueOnce(new Error("chunk load failed"))
      .mockResolvedValueOnce({
        default: () => <div>Lazy panel loaded</div>,
      });

    render(
      <RetryableLazyContent load={load} fallback={<div>Loading panel</div>} />,
    );

    expect(
      await screen.findByText("This panel failed to load."),
    ).toBeInTheDocument();

    // When
    await user.click(screen.getByRole("button", { name: "Retry" }));

    // Then
    expect(await screen.findByText("Lazy panel loaded")).toBeInTheDocument();
    expect(load).toHaveBeenCalledTimes(2);
    consoleError.mockRestore();
  });
});
