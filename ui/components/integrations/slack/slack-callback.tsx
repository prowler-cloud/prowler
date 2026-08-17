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
import { SLACK_REASON_TOKEN } from "@/lib/integrations/slack-errors";

const SLACK_INTEGRATION_PATH = "/integrations/slack";

const STATUS = {
  CONNECTING: "connecting",
  CONNECTED: "connected",
  FAILED: "failed",
} as const;

type Status = (typeof STATUS)[keyof typeof STATUS];

const UNCONFIRMED_COMPLETION_MESSAGE =
  "Prowler could not confirm whether the workspace was connected. Open the Slack integration page to check — if none is listed there, start the install again.";

const FAILURE_TITLE = "Slack workspace not connected";

/**
 * The API consumes the code and upserts the integration before it answers, so an
 * unreadable or missing answer can still mean a connected workspace. Kept short:
 * `AlertTitle` clamps to one line.
 */
const UNCONFIRMED_TITLE = "Slack install not confirmed";

const describeSlackError = (reason: string): string => {
  if (reason === "access_denied") {
    return "The install was not approved in Slack, so no workspace was connected.";
  }
  // `error` comes straight off the URL and is interpolated into Prowler's own
  // copy, so gate on the shape of a code: Slack publishes no closed set.
  return SLACK_REASON_TOKEN.test(reason)
    ? `Slack could not complete the install (${reason}).`
    : "Slack could not complete the install.";
};

/**
 * Slack's `code` is single-use: `hasStarted` holds the exchange to one run per
 * mount, and `router.replace` (not `push`) keeps a back navigation from
 * remounting onto a spent code.
 */
export const SlackCallback = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<Status>(STATUS.CONNECTING);
  const [workspaceName, setWorkspaceName] = useState<string | null>(null);
  const [failure, setFailure] = useState<string>("");
  const [failureTitle, setFailureTitle] = useState<string>(FAILURE_TITLE);
  const hasStarted = useRef(false);

  useEffect(() => {
    if (hasStarted.current) return;
    hasStarted.current = true;

    const slackError = searchParams.get("error");
    const code = searchParams.get("code");
    const state = searchParams.get("state");

    // Slack answers a declined install with `error` and no code, so there is
    // nothing to exchange.
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
          result.integration.attributes?.configuration?.team_name ?? null,
        );
        setStatus(STATUS.CONNECTED);
        router.replace(SLACK_INTEGRATION_PATH);
        return;
      }

      if ("unavailable" in result) {
        setFailure("Slack is not available in this environment yet.");
      } else if ("rateLimited" in result) {
        setFailure(result.message);
      } else if ("unconfirmed" in result) {
        setFailure(result.message);
        setFailureTitle(UNCONFIRMED_TITLE);
      } else {
        setFailure(result.error);
      }
      setStatus(STATUS.FAILED);
    };

    // A rejection here means the call never came back (stale action id after a
    // deploy, HTML 502): error boundaries cannot see a rejection awaited inside
    // an effect, and the once-guard blocks a retry, so the page would spin.
    void complete().catch(() => {
      setFailure(UNCONFIRMED_COMPLETION_MESSAGE);
      setFailureTitle(UNCONFIRMED_TITLE);
      setStatus(STATUS.FAILED);
    });
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
        <AlertTitle>{failureTitle}</AlertTitle>
        <AlertDescription>{failure}</AlertDescription>
      </Alert>
      <Button asChild variant="outline">
        <Link href={SLACK_INTEGRATION_PATH}>Back to Slack integration</Link>
      </Button>
    </div>
  );
};
