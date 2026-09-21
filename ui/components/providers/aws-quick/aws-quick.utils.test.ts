import { describe, expect, it } from "vitest";

import {
  awsQuickRoleSchema,
  awsQuickStaticSchema,
  parseAwsAccountIdFromRoleArn,
  resolveAwsQuickAccountId,
} from "./aws-quick.utils";
import { AWS_QUICK_ACCESS_METHOD } from "./types";

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

describe("awsQuickRoleSchema", () => {
  it("rejects a malformed ARN with a readable message", () => {
    const result = awsQuickRoleSchema.safeParse({ roleArn: "not-an-arn" });

    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain("valid IAM Role ARN");
  });

  it("requires the ARN", () => {
    const result = awsQuickRoleSchema.safeParse({ roleArn: "   " });

    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toBe("IAM Role ARN is required");
  });
});

describe("awsQuickStaticSchema", () => {
  it("accepts keys without a session token", () => {
    const result = awsQuickStaticSchema.safeParse({
      accountId: "123456789012",
      awsAccessKeyId: "AKIA",
      awsSecretAccessKey: "secret",
    });

    expect(result.success).toBe(true);
  });

  it("rejects a non 12-digit account id", () => {
    const result = awsQuickStaticSchema.safeParse({
      accountId: "1234",
      awsAccessKeyId: "AKIA",
      awsSecretAccessKey: "secret",
    });

    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.path).toEqual(["accountId"]);
  });
});

describe("resolveAwsQuickAccountId", () => {
  it("derives the account from the role ARN", () => {
    expect(
      resolveAwsQuickAccountId({
        method: AWS_QUICK_ACCESS_METHOD.ROLE,
        values: { roleArn: "arn:aws:iam::210987654321:role/ProwlerScan" },
      }),
    ).toBe("210987654321");
  });

  it("uses the typed account id for static keys", () => {
    expect(
      resolveAwsQuickAccountId({
        method: AWS_QUICK_ACCESS_METHOD.STATIC,
        values: {
          accountId: " 123456789012 ",
          awsAccessKeyId: "AKIA",
          awsSecretAccessKey: "secret",
        },
      }),
    ).toBe("123456789012");
  });
});
