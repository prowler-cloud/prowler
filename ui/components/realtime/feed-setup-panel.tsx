"use client";

import { useId, useState } from "react";

import {
  getRealtimeFeed,
  pollRealtimeFeed,
  saveRealtimeFeed,
} from "@/actions/realtime";
import { FeedStatusBadge } from "@/components/realtime/realtime-badges";
import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import {
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { TemplateGuide } from "@/components/realtime/template-guide";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { Input } from "@/components/shadcn/input/input";
import { useToast } from "@/components/shadcn/toast";
import { formatRelativeTime } from "@/lib/realtime/display";
import { realtimeFeedSchema } from "@/lib/realtime/policy-schema";
import { FEED_CLOUDFORMATION, FEED_TERRAFORM } from "@/lib/realtime/templates";
import type { RealtimeFeed } from "@/types/realtime";

const DEFAULT_REGION = "us-east-1";

interface FeedFormProps {
  providerId: string;
  feed: RealtimeFeed | null;
  canManage: boolean;
  onSaved: (feed: RealtimeFeed) => void;
}

function FeedForm({ providerId, feed, canManage, onSaved }: FeedFormProps) {
  const { toast } = useToast();
  const queueId = useId();
  const regionId = useId();
  const [queueUrl, setQueueUrl] = useState(feed?.queue_url ?? "");
  const [region, setRegion] = useState(feed?.region ?? DEFAULT_REGION);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    const parsed = realtimeFeedSchema.safeParse({
      queue_url: queueUrl,
      region,
    });
    if (!parsed.success) {
      setErrors(
        Object.fromEntries(
          parsed.error.issues.map((issue) => [
            String(issue.path[0]),
            issue.message,
          ]),
        ),
      );
      return;
    }
    setErrors({});
    setSaving(true);
    const result = await saveRealtimeFeed({
      providerId,
      feedId: feed?.id,
      feed: parsed.data,
    });
    setSaving(false);
    if (result.ok) {
      onSaved(result.data);
      toast({
        title: parsed.data.queue_url
          ? "Real-time queue saved"
          : "Using CloudTrail lookup",
      });
    } else {
      setErrors(result.fieldErrors ?? {});
      toast({
        variant: "destructive",
        title: "Could not save the feed",
        description: result.error,
      });
    }
  };

  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-[2fr_1fr]">
        <Field>
          <FieldLabel htmlFor={queueId}>SQS queue URL</FieldLabel>
          <Input
            id={queueId}
            value={queueUrl}
            disabled={!canManage || saving}
            placeholder="https://sqs.us-east-1.amazonaws.com/123456789012/prowler-realtime-events"
            aria-invalid={Boolean(errors.queue_url)}
            aria-describedby={errors.queue_url ? `${queueId}-error` : undefined}
            onChange={(event) => setQueueUrl(event.target.value)}
          />
          {errors.queue_url && (
            <FieldError id={`${queueId}-error`}>{errors.queue_url}</FieldError>
          )}
        </Field>
        <Field>
          <FieldLabel htmlFor={regionId}>Queue region</FieldLabel>
          <Input
            id={regionId}
            value={region}
            disabled={!canManage || saving}
            aria-invalid={Boolean(errors.region)}
            aria-describedby={errors.region ? `${regionId}-error` : undefined}
            onChange={(event) => setRegion(event.target.value)}
          />
          {errors.region && (
            <FieldError id={`${regionId}-error`}>{errors.region}</FieldError>
          )}
        </Field>
      </div>
      <p className="text-text-neutral-tertiary text-xs">
        Leave the queue URL empty to use CloudTrail lookup.
      </p>
      {canManage ? (
        <div>
          <Button type="submit" disabled={saving}>
            {saving ? "Saving…" : feed ? "Save feed" : "Create feed"}
          </Button>
        </div>
      ) : (
        <p className="text-text-neutral-tertiary text-sm">
          Read only: changing the feed needs the Manage Realtime permission.
        </p>
      )}
    </form>
  );
}

interface FeedSetupPanelProps {
  providerId: string;
  canManage: boolean;
  /** Called after a poll was queued, so the stream can refresh. */
  onPolled?: () => void;
  /** Called after the feed was created or changed. */
  onFeedChanged?: (feed: RealtimeFeed) => void;
}

/** The provider's event feed: status, "check now", and the queue form. */
export function FeedSetupPanel({
  providerId,
  canManage,
  onPolled,
  onFeedChanged,
}: FeedSetupPanelProps) {
  const { toast } = useToast();
  const [polling, setPolling] = useState(false);
  const feedResource = useRealtimeResource(
    () => getRealtimeFeed(providerId),
    `feed:${providerId}`,
    { intervalMs: 15_000 },
  );
  const feed = feedResource.data ?? null;

  const checkNow = async () => {
    if (!feed) return;
    setPolling(true);
    const result = await pollRealtimeFeed(feed.id);
    setPolling(false);
    if (result.ok) {
      toast({
        title: "Check requested",
        description: "New events appear in the stream within moments.",
      });
      onPolled?.();
      feedResource.reload();
    } else {
      toast({
        variant: "destructive",
        title: "Could not start the check",
        description: result.error,
      });
    }
  };

  const startLookup = async () => {
    const result = await saveRealtimeFeed({
      providerId,
      feed: { queue_url: "", region: DEFAULT_REGION },
    });
    if (result.ok) {
      feedResource.setData(result.data);
      onFeedChanged?.(result.data);
    } else
      toast({
        variant: "destructive",
        title: "Could not create the feed",
        description: result.error,
      });
  };

  return (
    <RealtimeSection
      title="Event feed"
      description="How Prowler Realtime learns about changes in this AWS account."
    >
      {feedResource.loading ? (
        <PanelLoading label="Loading the feed" />
      ) : feedResource.failure ? (
        <PanelFailure
          failure={feedResource.failure}
          onRetry={feedResource.reload}
          subject="the feed"
        />
      ) : (
        <div className="flex flex-col gap-4">
          <Alert variant="info">
            <AlertTitle>Real time or a few minutes behind</AlertTitle>
            <AlertDescription>
              <p>
                With an SQS queue, risky API calls reach Prowler Realtime in
                near real time. Without one, Prowler Realtime polls CloudTrail
                LookupEvents, which trails by a few minutes.
              </p>
            </AlertDescription>
          </Alert>
          <TemplateGuide
            cloudformation={FEED_CLOUDFORMATION}
            terraform={FEED_TERRAFORM}
            steps={[
              <>
                Apply the template below in this AWS account, as CloudFormation
                (stack) or Terraform, in each region you want to watch.
                Global-service events (IAM, S3 account settings) arrive in
                us-east-1.
              </>,
              <>
                It creates an SQS queue, an EventBridge rule for risky API
                calls, and read-only access to that queue for your{" "}
                <code className="text-xs">ProwlerScan</code> role. Nothing is
                changed in your account beyond that.
              </>,
              <>
                Copy the <code className="text-xs">QueueUrl</code> output and
                paste it below.
              </>,
            ]}
          />

          {feed ? (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              <FeedStatusBadge status={feed.status} />
              <span className="text-text-neutral-secondary text-sm">
                {feed.queue_url
                  ? "Real time (SQS)"
                  : "CloudTrail lookup (delayed)"}
              </span>
              <span className="text-text-neutral-tertiary text-xs">
                Last polled {formatRelativeTime(feed.last_polled_at)}
              </span>
              <span className="text-text-neutral-tertiary text-xs">
                Last event {formatRelativeTime(feed.last_event_at)}
              </span>
              {canManage && (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={polling}
                  onClick={() => void checkNow()}
                >
                  {polling ? "Checking…" : "Check now"}
                </Button>
              )}
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-text-neutral-secondary text-sm">
                No feed yet for this account.
              </span>
              {canManage && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => void startLookup()}
                >
                  Start with CloudTrail lookup
                </Button>
              )}
            </div>
          )}

          {feed?.last_error && (
            <Alert variant="error">
              <AlertTitle>The last poll failed</AlertTitle>
              <AlertDescription>
                <p>{feed.last_error}</p>
              </AlertDescription>
            </Alert>
          )}

          <FeedForm
            key={`${feed?.id ?? "new"}:${feed?.queue_url ?? ""}`}
            providerId={providerId}
            feed={feed}
            canManage={canManage}
            onSaved={(saved) => {
              feedResource.setData(saved);
              onFeedChanged?.(saved);
            }}
          />
        </div>
      )}
    </RealtimeSection>
  );
}
