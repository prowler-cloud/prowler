export const WIZARD_FOOTER_ACTION_TYPE = {
  BUTTON: "button",
  SUBMIT: "submit",
} as const;

export type WizardFooterActionType =
  (typeof WIZARD_FOOTER_ACTION_TYPE)[keyof typeof WIZARD_FOOTER_ACTION_TYPE];

export interface WizardFooterConfig {
  showBack: boolean;
  backLabel: string;
  backDisabled?: boolean;
  onBack?: () => void;
  showAction: boolean;
  actionLabel: string;
  actionDisabled?: boolean;
  actionType: WizardFooterActionType;
  actionFormId?: string;
  onAction?: () => void;
}
