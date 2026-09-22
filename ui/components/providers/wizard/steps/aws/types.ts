export const AWS_ACCESS_METHOD = {
  ROLE: "role",
  CREDENTIALS: "credentials",
} as const;

export type AwsAccessMethod =
  (typeof AWS_ACCESS_METHOD)[keyof typeof AWS_ACCESS_METHOD];

/** What the step publishes so the wizard can draw its footer. */
export interface AwsConnectUiState {
  showBack: boolean;
  showAction: boolean;
  actionLabel: string;
  actionDisabled: boolean;
  isLoading: boolean;
}
