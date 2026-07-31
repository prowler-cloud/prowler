import { isCloud } from "./shared/env";

export const PROWLER_CLOUD_ONLY_TOOLTIP = "Available only in Prowler Cloud";

export const isGroupedJiraDispatchEnabled = (): boolean => isCloud();
