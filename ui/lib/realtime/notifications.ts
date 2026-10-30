import { humanize } from "@/lib/realtime/display";
import {
  REALTIME_RECIPIENT_STATUS,
  type RealtimeEmailTarget,
  type RealtimeNotifications,
  type RealtimeNotificationTargets,
} from "@/types/realtime";

export const SLACK_INTEGRATIONS_PATH = "/integrations";
export const ALERTS_PATH = "/alerts";

/** Only a recipient who confirmed by email can be sent to. */
export const isSelectableRecipient = (target: RealtimeEmailTarget): boolean =>
  target.status === REALTIME_RECIPIENT_STATUS.CONFIRMED;

export const recipientStatusLabel = (status: string): string =>
  humanize(status);

/** Add or remove one id, keeping order and uniqueness. */
export const toggleId = (
  ids: string[],
  id: string,
  selected: boolean,
): string[] =>
  selected
    ? ids.includes(id)
      ? ids
      : [...ids, id]
    : ids.filter((item) => item !== id);

/** True when two alert settings would send the same alerts to the same places. */
export const sameNotifications = (
  a: RealtimeNotifications,
  b: RealtimeNotifications,
): boolean => JSON.stringify(a) === JSON.stringify(b);

/** One line per channel for the review step; nothing on means nothing is sent. */
export const notificationsSummary = (
  notifications: RealtimeNotifications,
  targets?: RealtimeNotificationTargets,
): string[] => {
  const lines: string[] = [];
  if (notifications.slack.enabled) {
    const names = notifications.slack.channel_ids.map((id) => {
      const found = targets?.slack.find((item) => item.channel_id === id);
      return found ? `#${found.name.replace(/^#/, "")}` : id;
    });
    lines.push(`Slack: ${names.join(", ") || "no channel selected"}`);
  }
  if (notifications.email.enabled) {
    const emails = notifications.email.recipient_ids.map(
      (id) => targets?.email.find((item) => item.id === id)?.email ?? id,
    );
    lines.push(`Email: ${emails.join(", ") || "no recipient selected"}`);
  }
  if (lines.length > 0) {
    lines.push(`From severity: ${humanize(notifications.min_severity)}`);
  }
  return lines;
};
