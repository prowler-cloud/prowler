import { CircleAlert, Info } from "lucide-react";
import Link from "next/link";

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
} from "@/components/shadcn";

import {
  ATTACK_PATHS_VIEW_STATES,
  type AttackPathsViewState,
} from "../_lib/get-attack-paths-view-state";

interface AttackPathsStatusPanelProps {
  state: AttackPathsViewState;
  progress?: number;
  onRetry?: () => void;
}

/**
 * Full-page status message shown whenever the Attack Paths graph is not yet
 * queryable. The page renders the normal workflow instead once `state` is
 * `READY` (this component renders nothing for `READY`/`LOADING`).
 */
export const AttackPathsStatusPanel = ({
  state,
  progress = 0,
  onRetry,
}: AttackPathsStatusPanelProps) => {
  if (state === ATTACK_PATHS_VIEW_STATES.ERROR) {
    return (
      <Alert variant="error">
        <CircleAlert className="size-4" />
        <AlertTitle>Couldn&apos;t load scans</AlertTitle>
        <AlertDescription className="flex flex-col items-start gap-3">
          <span>Something went wrong loading your scans.</span>
          {onRetry ? (
            <Button variant="outline" size="sm" onClick={onRetry}>
              Retry
            </Button>
          ) : null}
        </AlertDescription>
      </Alert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.NO_SCANS) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertTitle>No scans available</AlertTitle>
        <AlertDescription>
          <span>
            You need to run a scan before you can analyze attack paths.{" "}
            <Link href="/scans" className="font-medium underline">
              Go to Scan Jobs
            </Link>
          </span>
        </AlertDescription>
      </Alert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.SCAN_RUNNING) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertTitle>Scan in progress</AlertTitle>
        <AlertDescription>
          <span>
            Your scan is running. Attack Paths will be available once it
            completes.
          </span>
        </AlertDescription>
      </Alert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.GRAPH_BUILDING) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertTitle>Preparing Attack Paths data</AlertTitle>
        <AlertDescription>
          <span>
            We&apos;re building the graph from your latest scan ({progress}%).
            This will be ready shortly.
          </span>
        </AlertDescription>
      </Alert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.NO_GRAPH_DATA) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertTitle>No Attack Paths data</AlertTitle>
        <AlertDescription>
          <span>Your scan completed but didn&apos;t produce graph data.</span>
        </AlertDescription>
      </Alert>
    );
  }

  return null;
};
