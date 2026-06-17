import { CircleAlert, Info } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

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

interface StatusAlertProps {
  variant: "info" | "error";
  title: string;
  descriptionClassName?: string;
  children: ReactNode;
}

const StatusAlert = ({
  variant,
  title,
  descriptionClassName,
  children,
}: StatusAlertProps) => {
  const Icon = variant === "error" ? CircleAlert : Info;
  return (
    <Alert variant={variant}>
      <Icon className="size-4" />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription className={descriptionClassName}>
        {children}
      </AlertDescription>
    </Alert>
  );
};

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
      <StatusAlert
        variant="error"
        title="Couldn't load scans"
        descriptionClassName="flex flex-col items-start gap-3"
      >
        <span>Something went wrong loading your scans.</span>
        {onRetry ? (
          <Button variant="outline" size="sm" onClick={onRetry}>
            Retry
          </Button>
        ) : null}
      </StatusAlert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.NO_SCANS) {
    return (
      <StatusAlert variant="info" title="No scans available">
        <span>
          You need to run a scan before you can analyze attack paths.{" "}
          <Link href="/scans" className="font-medium underline">
            Go to Scan Jobs
          </Link>
        </span>
      </StatusAlert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.SCAN_PENDING) {
    return (
      <StatusAlert variant="info" title="Scan in progress">
        <span>
          Your scan is queued. Attack Paths will be available once it completes.
        </span>
      </StatusAlert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.GRAPH_BUILDING) {
    return (
      <StatusAlert variant="info" title="Preparing Attack Paths data">
        <span>
          We&apos;re building the graph from your latest scan ({progress}%).
          This will be ready shortly.
        </span>
      </StatusAlert>
    );
  }

  if (state === ATTACK_PATHS_VIEW_STATES.NO_GRAPH_DATA) {
    return (
      <StatusAlert variant="info" title="No Attack Paths data">
        <span>This scan didn&apos;t produce Attack Paths data.</span>
      </StatusAlert>
    );
  }

  return null;
};
