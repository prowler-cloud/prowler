const AWS_ROLE_ARN_PATTERN =
  /^arn:aws(?:-[a-z]+)*:iam::(\d{12}):role\/[\w+=,.@/-]+$/;

export const AWS_ROLE_ARN_MESSAGE =
  "Must be a valid IAM Role ARN (e.g. arn:aws:iam::123456789012:role/ProwlerScan)";

/** The 12-digit account id embedded in an IAM role ARN, or null when malformed. */
export const parseAwsAccountIdFromRoleArn = (roleArn: string) =>
  AWS_ROLE_ARN_PATTERN.exec(roleArn.trim())?.[1] ?? null;
