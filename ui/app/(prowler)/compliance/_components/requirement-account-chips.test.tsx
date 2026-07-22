import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { CrossAccountAccountRef } from "../_types";
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

  it("collapses to per-status counts beyond two accounts", () => {
    const meta = [
      account(1, "prod"),
      account(2, "staging"),
      account(3, "dev"),
      account(4, null),
    ];
    render(
      <RequirementAccountChips
        accounts={{
          [meta[0].id]: "FAIL",
          [meta[1].id]: "FAIL",
          [meta[2].id]: "PASS",
          [meta[3].id]: "MANUAL",
        }}
        accountMeta={meta}
      />,
    );

    // Constant-footprint summary: one count per status present, no
    // per-account labels inline.
    const summary = screen.getByTestId("requirement-status-summary");
    expect(summary).toHaveTextContent("Fail×2");
    expect(summary).toHaveTextContent("Manual×1");
    expect(summary).toHaveTextContent("Pass×1");
    expect(screen.queryByText("prod")).not.toBeInTheDocument();
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
