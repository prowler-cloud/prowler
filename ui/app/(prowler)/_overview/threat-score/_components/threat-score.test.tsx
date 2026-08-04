import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ThreatScore } from "./threat-score";

describe("ThreatScore", () => {
  it("keeps the card compact when the overview row is horizontal", () => {
    render(<ThreatScore score={75} />);

    const card = screen
      .getByText("Prowler ThreatScore")
      .closest('[data-slot="card"]');

    expect(card).toHaveClass("min-w-0", "flex-1", "min-[485px]:min-w-[312px]");
    expect(card).not.toHaveClass("max-w-[312px]");
  });
});
