export const AWS_ACCESS_METHOD = {
  ROLE: "role",
  CREDENTIALS: "credentials",
} as const;

export type AwsAccessMethod =
  (typeof AWS_ACCESS_METHOD)[keyof typeof AWS_ACCESS_METHOD];
