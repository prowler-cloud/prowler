export const AWS_QUICK_ACCESS_METHOD = {
  ROLE: "role",
  STATIC: "static",
} as const;

export type AwsQuickAccessMethod =
  (typeof AWS_QUICK_ACCESS_METHOD)[keyof typeof AWS_QUICK_ACCESS_METHOD];

export const AWS_QUICK_STEP = {
  CONNECT: 0,
  NAME: 1,
} as const;

export type AwsQuickStep = (typeof AWS_QUICK_STEP)[keyof typeof AWS_QUICK_STEP];
