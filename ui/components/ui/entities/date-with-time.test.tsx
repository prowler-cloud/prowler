import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DateWithTime } from "./date-with-time";

describe("DateWithTime", () => {
  it("uses a single dash placeholder when date is empty", () => {
    render(<DateWithTime dateTime="" />);

    expect(screen.getByText("-")).toBeInTheDocument();
    expect(screen.queryByText("--")).not.toBeInTheDocument();
  });
});
