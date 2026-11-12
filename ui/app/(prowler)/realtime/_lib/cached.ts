import "server-only";

import { cache } from "react";

import {
  getRealtimeDemo,
  getRealtimeInsight,
} from "@/app/(prowler)/realtime/_actions";

/** The overview, read once per request: the header and the Overview tab share it. */
export const getOverview = cache((providerId: string, demo: boolean) =>
  demo
    ? getRealtimeDemo("overview")
    : getRealtimeInsight("overview", providerId),
);
