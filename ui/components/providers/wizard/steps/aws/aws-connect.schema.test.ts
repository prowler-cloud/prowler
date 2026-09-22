import { describe, expect, it } from "vitest";

import { awsRoleConnectSchema } from "./aws-connect.schema";

const roleValues = {
  providerId: "",
  providerType: "aws",
  providerAlias: "",
  credentials_type: "aws-sdk-default",
  role_arn: "arn:aws:iam::123456789012:role/ProwlerScan",
  external_id: "",
  aws_access_key_id: "",
  aws_secret_access_key: "",
  aws_session_token: "",
  role_session_name: "",
  session_duration: "3600",
};

const issuesOf = (values: Record<string, string>) => {
  const result = awsRoleConnectSchema.safeParse(values);
  return result.success
    ? []
    : result.error.issues.map((issue) => [issue.path.join("."), issue.message]);
};

describe("awsRoleConnectSchema", () => {
  it("accepts the ARN alone, leaving the role to the host's credentials", () => {
    expect(issuesOf(roleValues)).toEqual([]);
  });

  it("accepts a full static key pair", () => {
    expect(
      issuesOf({
        ...roleValues,
        aws_access_key_id: "AKIAEXAMPLE",
        aws_secret_access_key: "secret",
      }),
    ).toEqual([]);
  });

  it("points at the missing half of a key pair", () => {
    expect(
      issuesOf({ ...roleValues, aws_access_key_id: "AKIAEXAMPLE" }),
    ).toEqual([
      ["aws_secret_access_key", "AWS Secret Access Key is required."],
    ]);
    expect(
      issuesOf({ ...roleValues, aws_secret_access_key: "secret" }),
    ).toEqual([["aws_access_key_id", "AWS Access Key ID is required."]]);
  });
});
