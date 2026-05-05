import {
  ALERT_ERROR_CODES,
  type AlertPublicResponse,
  type AlertsActionResult,
} from "../_types";

const ALERTS_DISABLED_MESSAGE =
  "Custom alerts are only available in Prowler Cloud.";

export const isAlertsEnabled = () =>
  process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";

export const buildAlertsDisabledResult = <T>(): AlertsActionResult<T> => ({
  ok: false,
  error: {
    code: ALERT_ERROR_CODES.FORBIDDEN,
    detail: ALERTS_DISABLED_MESSAGE,
    status: 403,
  },
});

export const buildAlertsDisabledPublicResponse = (): AlertPublicResponse => ({
  state: "network_error",
  message: ALERTS_DISABLED_MESSAGE,
});
