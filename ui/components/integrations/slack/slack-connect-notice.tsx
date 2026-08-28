"use client";

import { AlertCircle, CircleCheck } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import type { ComponentProps } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  readSlackConnectOutcome,
  SLACK_CONNECT_PARAMS,
  SLACK_CONNECT_STATUS,
} from "@/lib/integrations/slack-connect-status";
import type { SlackConnectOutcome } from "@/lib/integrations/slack-connect-status";
import {
  SLACK_GENERIC_ERROR_MESSAGE,
  SLACK_REASON_TOKEN,
  slackErrorMessage,
  slackRateLimitMessage,
} from "@/lib/integrations/slack-errors";

const FAILURE_TITLE = "Slack workspace not connected";

/**
 * The API consumes the code and upserts the integration before it answers, so
 * an unreadable or missing answer can still mean a connected workspace. Kept
 * short: `AlertTitle` clamps to one line.
 */
const UNCONFIRMED_TITLE = "Slack install not confirmed";

const describeSlackError = (reason: string | null): string => {
  if (reason === "access_denied") {
    return "The install was not approved in Slack, so no workspace was connected.";
  }
  // The reason came off the URL and is interpolated into Prowler's own copy,
  // so gate on the shape of a code (the contract already did — belt and
  // braces): Slack publishes no closed set.
  return reason && SLACK_REASON_TOKEN.test(reason)
    ? `Slack could not complete the install (${reason}).`
    : "Slack could not complete the install.";
};

interface NoticeContent {
  variant: ComponentProps<typeof Alert>["variant"];
  title: string;
  description: string;
}

const noticeFor = (outcome: SlackConnectOutcome): NoticeContent => {
  switch (outcome.status) {
    case SLACK_CONNECT_STATUS.CONNECTED:
      return {
        variant: "success",
        title: "Slack workspace connected",
        description: "You can now authorize the channels Prowler posts to.",
      };
    case SLACK_CONNECT_STATUS.SLACK_ERROR:
      return {
        variant: "error",
        title: FAILURE_TITLE,
        description: describeSlackError(outcome.reason),
      };
    case SLACK_CONNECT_STATUS.INCOMPLETE:
      return {
        variant: "error",
        title: FAILURE_TITLE,
        description:
          "Slack sent an incomplete response back, so the install could not be completed.",
      };
    case SLACK_CONNECT_STATUS.EXPIRED:
      return {
        variant: "error",
        title: FAILURE_TITLE,
        // Not "try again in a moment": a spent install link never recovers.
        description:
          "The install link from Slack had already been used or expired, so no workspace was connected. Start the install again.",
      };
    case SLACK_CONNECT_STATUS.UNAVAILABLE:
      return {
        variant: "error",
        title: FAILURE_TITLE,
        description: "Slack is not available in this environment yet.",
      };
    case SLACK_CONNECT_STATUS.RATE_LIMITED:
      return {
        variant: "error",
        title: FAILURE_TITLE,
        description: slackRateLimitMessage(outcome.retryAfterSeconds),
      };
    case SLACK_CONNECT_STATUS.UNCONFIRMED:
      return {
        variant: "error",
        title: UNCONFIRMED_TITLE,
        description:
          "Prowler could not confirm whether the workspace was connected. If none is listed below, start the install again.",
      };
    case SLACK_CONNECT_STATUS.ERROR:
      return {
        variant: "error",
        title: FAILURE_TITLE,
        // Known codes keep Prowler's wording; the URL carries no free text, so
        // everything else reads as the generic refusal.
        description: slackErrorMessage(
          { code: outcome.code },
          SLACK_GENERIC_ERROR_MESSAGE,
        ),
      };
  }
};

/**
 * The outcome the OAuth callback route left in the query string, shown once.
 * The params are stripped via the History API rather than `router.replace`: an
 * RSC refetch here buys nothing (the exchange already revalidated), and a
 * client navigation is exactly what the callback stopped relying on.
 */
interface SlackConnectNoticeProps {
  hasConnectedWorkspace: boolean;
}

export const SlackConnectNotice = ({
  hasConnectedWorkspace,
}: SlackConnectNoticeProps) => {
  const searchParams = useSearchParams();
  // Read once into state: the notice has to survive its own URL cleanup.
  const [outcome] = useState<SlackConnectOutcome | null>(() =>
    readSlackConnectOutcome(new URLSearchParams(searchParams.toString())),
  );

  useMountEffect(() => {
    if (!outcome) return;
    const params = new URLSearchParams(window.location.search);
    SLACK_CONNECT_PARAMS.forEach((param) => params.delete(param));
    const query = params.toString();
    const fragment = window.location.hash;
    window.history.replaceState(
      null,
      "",
      query
        ? `${window.location.pathname}?${query}${fragment}`
        : `${window.location.pathname}${fragment}`,
    );
  });

  if (!outcome) return null;

  const verifiedOutcome =
    outcome.status === SLACK_CONNECT_STATUS.CONNECTED && !hasConnectedWorkspace
      ? { ...outcome, status: SLACK_CONNECT_STATUS.UNCONFIRMED }
      : outcome;
  const notice = noticeFor(verifiedOutcome);

  return (
    <Alert data-slack-connect-notice variant={notice.variant}>
      {notice.variant === "success" ? <CircleCheck /> : <AlertCircle />}
      <AlertTitle>{notice.title}</AlertTitle>
      <AlertDescription>{notice.description}</AlertDescription>
    </Alert>
  );
};
