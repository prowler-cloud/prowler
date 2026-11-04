import { humanize } from "@/app/(prowler)/realtime/_lib/display";
import {
  REALTIME_RECIPIENT_STATUS,
  type RealtimeEmailTarget,
} from "@/app/(prowler)/realtime/_types";

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
