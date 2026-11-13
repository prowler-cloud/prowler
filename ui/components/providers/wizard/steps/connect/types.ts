/** What the footer's main action does: submit the step's form, or close the wizard. */
export const CONNECT_ACTION_KIND = {
  SUBMIT: "submit",
  CLOSE: "close",
} as const;

export type ConnectActionKind =
  (typeof CONNECT_ACTION_KIND)[keyof typeof CONNECT_ACTION_KIND];

/** What the connect step publishes so the wizard can draw its footer. */
export interface ConnectUiState {
  showBack: boolean;
  showAction: boolean;
  actionLabel: string;
  actionDisabled: boolean;
  isLoading: boolean;
  /** Absent means submit. */
  actionKind?: ConnectActionKind;
}

/** Callbacks every access form of the connect step receives. */
export interface ConnectFormProps {
  formId: string;
  /** The wizard was opened on an existing account: its identity is fixed. */
  locked: boolean;
  submitLabel: string;
  onConnected: () => void;
  onBusyChange: (isBusy: boolean) => void;
  onUiStateChange: (state: ConnectUiState) => void;
}
