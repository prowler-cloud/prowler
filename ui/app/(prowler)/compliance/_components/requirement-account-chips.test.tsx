import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { AccountStatusMap, CrossAccountAccountRef } from "../_types";

import { RequirementAccountChips } from "./requirement-account-chips";

const account = (n: number, alias: string | null): CrossAccountAccountRef => ({
  id: `00000000-0000-4000-8000-00000000000${n}`,
  uid: `10000000000${n}`,
  alias,
});

describe("RequirementAccountChips", () => {
  it("shows inline labeled chips for up to two accounts", () => {
    const meta = [account(1, "prod"), account(2, null)];
    render(
      <RequirementAccountChips
        accounts={{ [meta[0].id]: "FAIL", [meta[1].id]: "PASS" }}
        accountMeta={meta}
      />,
    );

    expect(screen.getByText("prod")).toBeInTheDocument();
    expect(screen.getByText("100000000002")).toBeInTheDocument();
    expect(
      screen.queryByTestId("requirement-status-summary"),
    ).not.toBeInTheDocument();
  });

  it("collapses many accounts without hiding the full breakdown", async () => {
    const user = userEvent.setup();
    const meta = Array.from({ length: 13 }, (_, index) =>
      account(index + 1, `account-${index + 1}`),
    );
    const accounts: AccountStatusMap = Object.fromEntries(
      meta.map((entry, index) => {
        const status = index < 2 ? "FAIL" : index === 2 ? "MANUAL" : "PASS";
        return [entry.id, status];
      }),
    );

    render(<RequirementAccountChips accounts={accounts} accountMeta={meta} />);

    const summary = screen.getByRole("button", {
      name: "Show status breakdown for 13 accounts",
    });
    expect(summary).toHaveTextContent("Fail×2");
    expect(summary).toHaveTextContent("Manual×1");
    expect(summary).toHaveTextContent("Pass×10");
    expect(screen.queryByText("account-1")).not.toBeInTheDocument();

    await user.click(summary);

    expect(screen.getByText(/^account-1 \(/)).toBeVisible();
    expect(screen.getByText(/^account-13 \(/)).toBeVisible();
    expect(screen.queryByText(/more/)).not.toBeInTheDocument();
  });

  it("only counts accounts that contributed a status", () => {
    const meta = [account(1, "prod"), account(2, "staging"), account(3, "dev")];
    render(
      <RequirementAccountChips
        accounts={{ [meta[0].id]: "PASS", [meta[1].id]: "PASS" }}
        accountMeta={meta}
      />,
    );

    // Two contributing accounts → still inline, the silent third is ignored.
    expect(screen.getByText("prod")).toBeInTheDocument();
    expect(screen.getByText("staging")).toBeInTheDocument();
    expect(screen.queryByText("dev")).not.toBeInTheDocument();
  });
});
