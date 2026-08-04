import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ThreatScore } from "./threat-score";

describe("ThreatScore", () => {
  it("keeps the card full width until the overview row becomes horizontal", () => {
    render(<ThreatScore score={75} />);

    const card = screen
      .getByText("Prowler ThreatScore")
      .closest('[data-slot="card"]');

    expect(card).toHaveClass("xl:max-w-[312px]");
    expect(card).not.toHaveClass("lg:max-w-[312px]");
  });
});
