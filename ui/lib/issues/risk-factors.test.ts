import { describe, expect, it } from "vitest";

import { riskFactors } from "@/lib/issues/risk-factors";
import { IssueAttributes, LegAssessment, LegName } from "@/types/issues";

const leg = (state: LegAssessment["state"], text = `${state} text`) => ({
  state,
  text,
  evidence: [],
});

const issueWith = (
  overrides: Partial<IssueAttributes>,
  legs: Partial<Record<LegName, LegAssessment>> = {},
) =>
  ({ outcome: "", attacker_start: "", ...overrides, legs }) as IssueAttributes;

describe("riskFactors", () => {
  it("names every condition of an open path, explained by its leg", () => {
    const factors = riskFactors(
      issueWith(
        { attacker_start: "internet", outcome: "data_exposure" },
        {
          access: leg("yes", "No credential is needed."),
          target: leg("yes"),
          controls: leg("no", "The public access block is off."),
        },
      ),
    );

    expect(factors.map(({ label, variant }) => [label, variant])).toEqual([
      ["Internet-reachable", "error"],
      ["Access possible", "error"],
      ["Data exposure", "error"],
      ["No control blocking", "warning"],
    ]);
    expect(factors[1].title).toBe("No credential is needed.");
    expect(factors[3].title).toBe("The public access block is off.");
  });

  it("reads a control in force as the good news it is", () => {
    const factors = riskFactors(
      issueWith({ attacker_start: "foothold" }, { controls: leg("yes") }),
    );

    expect(factors.map(({ label, variant }) => [label, variant])).toEqual([
      ["Needs a foothold", "warning"],
      ["Blocked by a control", "success"],
    ]);
  });

  it("says nothing it cannot back: unknown legs and no start give no chips", () => {
    expect(
      riskFactors(
        issueWith(
          {},
          {
            access: leg("unknown"),
            target: leg("partial"),
            controls: leg("unknown"),
          },
        ),
      ),
    ).toEqual([]);
    // The unmodelled issue carries no legs at all.
    expect(riskFactors(issueWith({}))).toEqual([]);
  });

  it("falls back to a generic target label when the path has no outcome", () => {
    expect(
      riskFactors(issueWith({}, { target: leg("yes") })).map((f) => f.label),
    ).toEqual(["Worth taking"]);
  });
});
