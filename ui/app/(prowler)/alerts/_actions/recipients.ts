"use server";

import type { AlertRecipient, AlertsActionResult } from "../_types";
import { alertsRequest } from "./_request";

const RECIPIENTS_PATH = "/alerts/recipients";

export interface AlertRecipientsListResponse {
  data: AlertRecipient[];
  meta?: {
    pagination?: { count: number; pages: number; page: number };
  };
}

export const listAlertRecipients = async (
  searchParams?: URLSearchParams,
): Promise<AlertsActionResult<AlertRecipientsListResponse>> =>
  alertsRequest<AlertRecipientsListResponse>(RECIPIENTS_PATH, {
    method: "GET",
    query: searchParams,
  });
