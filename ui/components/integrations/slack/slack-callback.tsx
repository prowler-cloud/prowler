"use client";

import { AlertCircle, CircleCheck, Loader2 } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { exchangeSlackOAuthCode } from "@/actions/integrations/slack";
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
} from "@/components/shadcn";

const SLACK_INTEGRATION_PATH = "/integrations/slack";

const STATUS = {
  CONNECTING: "connecting",
  CONNECTED: "connected",
  FAILED: "failed",
} as const;

type Status = (typeof STATUS)[keyof typeof STATUS];

/** Turn the `error` Slack puts on the callback URL into something readable. */
const describeSlackError = (reason: string): string =>
  reason === "access_denied"
    ? "The install was not approved in Slack, so no workspace was connected."
    : `Slack could not complete the install (${reason}).`;

/**
 * Completes the Slack install after Slack redirects the user back here.
 *
 * The UI's only job on return is to forward `code` and `state` to the API,
 * which owns the OAuth secret, mints the state and consumes it — a completion
 * whose state it cannot match is refused there, and surfaced here.
 *
 * The exchange runs **exactly once**: the Slack code is single-use, so a second
 * invocation (a re-render, a Strict Mode double effect, a back navigation)
 * would burn it and report a failure for an install that actually succeeded.
 * The guard is the mechanism, not a nicety.
 */
export const SlackCallback = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<Status>(STATUS.CONNECTING);
  const [workspaceName, setWorkspaceName] = useState<string | null>(null);
  const [failure, setFailure] = useState<string>("");
  const hasStarted = useRef(false);

  useEffect(() => {
    if (hasStarted.current) return;
    hasStarted.current = true;

    const slackError = searchParams.get("error");
    const code = searchParams.get("code");
    const state = searchParams.get("state");

    // Slack answers a declined or rejected install with `error`, and no code —
    // there is nothing to exchange, so nothing is created.
    if (slackError) {
      setFailure(describeSlackError(slackError));
      setStatus(STATUS.FAILED);
      return;
    }

    if (!code || !state) {
      setFailure(
        "Slack sent an incomplete response back, so the install could not be completed.",
      );
      setStatus(STATUS.FAILED);
      return;
    }

    const complete = async () => {
      const result = await exchangeSlackOAuthCode({ code, state });

      if ("integration" in result) {
        setWorkspaceName(
          result.integration.attributes.configuration.team_name ?? null,
        );
        setStatus(STATUS.CONNECTED);
        router.replace(SLACK_INTEGRATION_PATH);
        return;
      }

      if ("unavailable" in result) {
        setFailure("Slack is not available in this environment yet.");
      } else if ("rateLimited" in result) {
        // Nothing is wrong with the install — Slack is just busy — so the user
        // is told when to come back, not that the environment lacks Slack.
        setFailure(result.message);
      } else {
        setFailure(result.error);
      }
      setStatus(STATUS.FAILED);
    };

    void complete();
  }, [router, searchParams]);

  if (status === STATUS.CONNECTING) {
    return (
      <div className="flex items-center gap-3 text-sm text-gray-600 dark:text-gray-300">
        <Loader2 className="animate-spin" size={16} />
        Connecting your Slack workspace...
      </div>
    );
  }

  if (status === STATUS.CONNECTED) {
    return (
      <Alert variant="success">
        <CircleCheck />
        <AlertTitle>
          Connected to {workspaceName ?? "your Slack workspace"}
        </AlertTitle>
        <AlertDescription>
          Taking you back to the Slack integration, where you can choose the
          channel Prowler posts to.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="flex flex-col items-start gap-4">
      <Alert variant="error">
        <AlertCircle />
        <AlertTitle>Slack workspace not connected</AlertTitle>
        <AlertDescription>{failure}</AlertDescription>
      </Alert>
      <Button asChild variant="outline">
        <Link href={SLACK_INTEGRATION_PATH}>Back to Slack integration</Link>
      </Button>
    </div>
  );
};
