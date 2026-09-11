import { describe, expect, it } from "vitest";

import { isRegistryEligible } from "./access";
describe("Registry access", () => {
  it.each([
    [true, true, true, true],
    [false, true, true, false],
    [true, false, true, false],
    [true, true, false, false],
    [true, true, undefined, false],
    [true, true, "true", false],
  ])(
    "allows only exact current authority",
    (cloud, flag, permission, expected) => {
      expect(isRegistryEligible(cloud, flag, permission)).toBe(expected);
    },
  );
});
