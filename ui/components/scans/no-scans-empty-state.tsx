import { Card, CardContent } from "@/components/shadcn";
import { SCAN_JOBS_TAB, SCAN_TAB_LABELS, type ScanJobsTab } from "@/types";

import { InfoIcon } from "../icons/Icons";

interface EmptyStateCopy {
  title: string;
  description: string;
  hint: string;
}

const EMPTY_STATE_COPY: Record<ScanJobsTab, EmptyStateCopy> = {
  [SCAN_JOBS_TAB.ACTIVE]: {
    title: "No scans in progress",
    description:
      "Scans currently running or queued will appear here when available.",
    hint: `Switch to ${SCAN_TAB_LABELS[SCAN_JOBS_TAB.COMPLETED]} to review past results, or to ${SCAN_TAB_LABELS[SCAN_JOBS_TAB.SCHEDULED]}.`,
  },
  [SCAN_JOBS_TAB.COMPLETED]: {
    title: "No completed scans yet",
    description:
      "Finished, failed, or cancelled scans will appear here once they wrap up.",
    hint: `Switch to ${SCAN_TAB_LABELS[SCAN_JOBS_TAB.ACTIVE]} to monitor ongoing scans, or to ${SCAN_TAB_LABELS[SCAN_JOBS_TAB.SCHEDULED]} to plan future runs.`,
  },
  [SCAN_JOBS_TAB.SCHEDULED]: {
    title: "No scheduled scans",
    description: "Scans scheduled to run later will appear here.",
    hint: `Switch to ${SCAN_TAB_LABELS[SCAN_JOBS_TAB.ACTIVE]} to monitor ongoing scans, or to ${SCAN_TAB_LABELS[SCAN_JOBS_TAB.COMPLETED]} to review past results.`,
  },
};

interface NoScansEmptyStateProps {
  tab: ScanJobsTab;
}

export function NoScansEmptyState({ tab }: NoScansEmptyStateProps) {
  const copy = EMPTY_STATE_COPY[tab];

  return (
    <Card variant="base">
      <CardContent className="flex w-full flex-col items-center gap-3 px-4 py-10 text-center">
        <InfoIcon className="h-8 w-8 text-gray-800 dark:text-white" />
        <h2 className="text-lg font-bold text-gray-800 dark:text-white">
          {copy.title}
        </h2>
        <p className="max-w-prose text-sm text-gray-600 dark:text-gray-300">
          {copy.description}
        </p>
        <p className="max-w-prose text-sm text-gray-600 dark:text-gray-300">
          {copy.hint}
        </p>
      </CardContent>
    </Card>
  );
}
