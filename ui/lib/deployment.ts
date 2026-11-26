import { isCloud } from "./shared/env";

export const isGroupedJiraDispatchEnabled = (): boolean => isCloud();
