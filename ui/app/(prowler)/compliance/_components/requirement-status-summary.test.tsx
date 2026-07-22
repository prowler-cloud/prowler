import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { RequirementStatusSummary } from "./requirement-status-summary";

describe("RequirementStatusSummary", () => {
  it("exposes the complete breakdown from a keyboard-accessible trigger", async () => {
    const user = userEvent.setup();
    const entries = Array.from({ length: 13 }, (_, index) => ({
      key: `account-${index}`,
      label: `Account ${index + 1}`,
      status: index === 0 ? ("FAIL" as const) : ("PASS" as const),
    }));

    render(<RequirementStatusSummary entries={entries} />);

    const trigger = screen.getByRole("button", {
      name: "Show status breakdown for 13 providers",
    });
    trigger.focus();
    expect(trigger).toHaveFocus();

    await user.click(trigger);

    expect(screen.getByText("Account 1")).toBeVisible();
    expect(screen.getByText("Account 13")).toBeVisible();
    expect(screen.queryByText(/more/)).not.toBeInTheDocument();
  });
});
