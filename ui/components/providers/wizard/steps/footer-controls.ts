export const WIZARD_FOOTER_ACTION_TYPE = {
  BUTTON: "button",
  SUBMIT: "submit",
} as const;

export type WizardFooterActionType =
  (typeof WIZARD_FOOTER_ACTION_TYPE)[keyof typeof WIZARD_FOOTER_ACTION_TYPE];

export type WizardFooterSecondaryActionVariant = "outline" | "link";

export interface WizardFooterConfig {
  showBack: boolean;
  backLabel: string;
  backDisabled?: boolean;
  onBack?: () => void;
  showSecondaryAction?: boolean;
  secondaryActionLabel?: string;
  secondaryActionDisabled?: boolean;
  secondaryActionVariant?: WizardFooterSecondaryActionVariant;
  secondaryActionType?: WizardFooterActionType;
  secondaryActionFormId?: string;
  onSecondaryAction?: () => void;
  showAction: boolean;
  actionLabel: string;
  actionDisabled?: boolean;
  actionType: WizardFooterActionType;
  actionFormId?: string;
  onAction?: () => void;
}
