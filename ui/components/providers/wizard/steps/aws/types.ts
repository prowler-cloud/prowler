export const AWS_ACCESS_METHOD = {
  ROLE: "role",
  CREDENTIALS: "credentials",
} as const;

export type AwsAccessMethod =
  (typeof AWS_ACCESS_METHOD)[keyof typeof AWS_ACCESS_METHOD];

/** What the footer's main action does: submit the step's form, or close the wizard. */
export const AWS_CONNECT_ACTION_KIND = {
  SUBMIT: "submit",
  CLOSE: "close",
} as const;

export type AwsConnectActionKind =
  (typeof AWS_CONNECT_ACTION_KIND)[keyof typeof AWS_CONNECT_ACTION_KIND];

/** What the step publishes so the wizard can draw its footer. */
export interface AwsConnectUiState {
  showBack: boolean;
  showAction: boolean;
  actionLabel: string;
  actionDisabled: boolean;
  isLoading: boolean;
  /** Absent means submit. */
  actionKind?: AwsConnectActionKind;
}
