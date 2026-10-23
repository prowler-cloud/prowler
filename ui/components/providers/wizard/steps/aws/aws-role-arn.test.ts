import { describe, expect, it } from "vitest";

import { parseAwsAccountIdFromRoleArn } from "./aws-role-arn";

describe("parseAwsAccountIdFromRoleArn", () => {
  it.each([
    ["arn:aws:iam::123456789012:role/ProwlerScan", "123456789012"],
    ["  arn:aws:iam::123456789012:role/path/ProwlerScan  ", "123456789012"],
    ["arn:aws-cn:iam::123456789012:role/ProwlerScan", "123456789012"],
    ["arn:aws-us-gov:iam::123456789012:role/Prowler@Scan", "123456789012"],
  ])("extracts the account id from %s", (arn, expected) => {
    expect(parseAwsAccountIdFromRoleArn(arn)).toBe(expected);
  });

  it.each([
    "",
    "123456789012",
    "arn:aws:iam::12345678901:role/ProwlerScan",
    "arn:aws:iam::123456789012:user/prowler",
    "arn:aws:s3:::bucket",
    "arn:aws:iam::123456789012:role/",
  ])("returns null for %s", (arn) => {
    expect(parseAwsAccountIdFromRoleArn(arn)).toBeNull();
  });
});
