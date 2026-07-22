import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Progress } from "./progress";

describe("Progress", () => {
  it("provides semantic indicator variants", () => {
    render(<Progress aria-label="Score" value={75} variant="warning" />);

    expect(
      screen.getByRole("progressbar", { name: "Score" }).firstChild,
    ).toHaveClass("bg-bg-warning");
  });
});
