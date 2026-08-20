import type {
  AlertCondition,
  AlertTriggerKind,
} from "@/app/(prowler)/alerts/_types";

export interface AlertFormValues {
  name: string;
  description: string;
  frequency: AlertTriggerKind;
  condition: AlertCondition;
  recipientEmails: string[];
  /** Slack channel ids drawn from the integration's authorized set. */
  slackChannels: string[];
  enabled: boolean;
}

export interface AlertFormSubmitResult {
  ok: boolean;
  alertId?: string;
  error?: string;
}
