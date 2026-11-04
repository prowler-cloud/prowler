import Link from "next/link";

import { safeExternalUrl } from "@/app/(prowler)/realtime/_lib/display";
import { configurationHref } from "@/app/(prowler)/realtime/_lib/routes";
import {
  REALTIME_ACTION_KIND,
  REALTIME_ACTION_STATUS,
  type RealtimeAction,
} from "@/app/(prowler)/realtime/_types";
import { Button } from "@/components/shadcn";

/** What the action produced: a PR link, the summary, or why nothing happened. */
export function ActionResult({
  action,
  providerId,
}: {
  action: RealtimeAction;
  providerId: string;
}) {
  const prUrl = safeExternalUrl(action.pr_url);
  if (prUrl) {
    return (
      <Button variant="link" size="link-sm" className="h-auto p-0" asChild>
        <a href={prUrl} target="_blank" rel="noopener noreferrer">
          View pull request
        </a>
      </Button>
    );
  }
  const noRepository =
    action.kind === REALTIME_ACTION_KIND.PROPOSAL &&
    action.status === REALTIME_ACTION_STATUS.QUEUED;
  return (
    <div className="flex flex-col gap-0.5">
      {action.summary && (
        <span className="text-text-neutral-secondary text-sm">
          {action.summary}
        </span>
      )}
      {noRepository && (
        <Button variant="link" size="link-xs" className="h-auto p-0" asChild>
          <Link href={configurationHref(providerId, "enforcement")}>
            Add a repository to open pull requests
          </Link>
        </Button>
      )}
    </div>
  );
}
