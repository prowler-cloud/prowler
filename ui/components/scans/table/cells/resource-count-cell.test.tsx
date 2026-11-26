import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { ResourceCountCell } from "./resource-count-cell";

describe("ResourceCountCell", () => {
  it("links a formatted positive count to the selected scan resources", async () => {
    // Given
    const user = userEvent.setup();
    render(<ResourceCountCell count={1234} scanId="scan /&?1" />);

    // When
    await user.tab();

    // Then
    const link = screen.getByRole("link", { name: "1,234" });
    expect(link).toHaveAttribute(
      "href",
      "/resources?filter[scan]=scan%20%2F%26%3F1",
    );
    expect(link).toHaveFocus();
  });

  it.each([0, undefined])("does not link a count of %s", (count) => {
    // Given / When
    render(<ResourceCountCell count={count} scanId="scan-1" />);

    // Then
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByText("0")).toBeVisible();
  });

  it.each([undefined, ""])(
    "does not link without a real scan id: %s",
    (scanId) => {
      // Given / When
      render(<ResourceCountCell count={7} scanId={scanId} />);

      // Then
      expect(screen.queryByRole("link")).not.toBeInTheDocument();
      expect(screen.getByText("7")).toBeVisible();
    },
  );
});
