import type {
  AlertCondition,
  AlertTriggerKind,
} from "@/app/(prowler)/alerts/_types";

export const ALERT_NOTIFICATION_METHODS = {
  EMAIL: "email",
} as const;

export type AlertNotificationMethod =
  (typeof ALERT_NOTIFICATION_METHODS)[keyof typeof ALERT_NOTIFICATION_METHODS];

export interface AlertFormValues {
  name: string;
  description: string;
  method: AlertNotificationMethod;
  frequency: AlertTriggerKind;
  condition: AlertCondition;
  recipientEmails: string[];
  enabled: boolean;
}

export interface AlertFormSubmitResult {
  ok: boolean;
  alertId?: string;
  error?: string;
}
