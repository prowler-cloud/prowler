import { describe, expect, it } from "vitest";

import { passScore, sumResults } from "./results";

describe("passScore", () => {
  it("scores passed over automated checks and leaves manual ones out", () => {
    expect(passScore({ pass: 3, fail: 1 })).toBe(75);
  });

  it("has no score when no automated check ran", () => {
    expect(passScore({ pass: 0, fail: 0 })).toBeNull();
  });
});

describe("sumResults", () => {
  it("adds up each result across the items", () => {
    expect(
      sumResults([
        { pass: 3, fail: 1, manual: 6 },
        { pass: 2, fail: 0, manual: 1 },
      ]),
    ).toEqual({ pass: 5, fail: 1, manual: 7 });
  });
});
