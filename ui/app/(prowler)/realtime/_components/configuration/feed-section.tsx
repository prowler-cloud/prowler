"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { RefreshCw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Controller, useForm, useFormState, useWatch } from "react-hook-form";

import {
  pollRealtimeFeed,
  saveRealtimeFeed,
} from "@/app/(prowler)/realtime/_actions";
import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import {
  type FeedFormValues,
  feedFormDefaults,
  feedFormSchema,
  toFeedInput,
} from "@/app/(prowler)/realtime/_lib/configuration-forms";
import {
  feedStatusBadge,
  formatRelativeTime,
} from "@/app/(prowler)/realtime/_lib/display";
import {
  feedSummary,
  regionFromQueueUrl,
} from "@/app/(prowler)/realtime/_lib/setup";
import {
  FEED_CLOUDFORMATION,
  FEED_TERRAFORM,
} from "@/app/(prowler)/realtime/_lib/templates";
import {
  REALTIME_FEED_SOURCE,
  type RealtimeFeed,
} from "@/app/(prowler)/realtime/_types";
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Field,
  FieldError,
  FieldLabel,
  Input,
} from "@/components/shadcn";
import {
  RadioGroup,
  RadioGroupItem,
} from "@/components/shadcn/radio-group/radio-group";
import { toast } from "@/components/shadcn/toast";
import { cn } from "@/lib/utils";

import { ConfigSectionCard, SectionFooter } from "./config-section-card";
import { reportSaveFailure, type SectionBaseProps } from "./section-props";
import { TemplateGuide } from "./template-guide";

const FEED_FIELDS = ["queue_url", "region"] as const;
const RECHECK_DELAY_MS = 8_000;

const SOURCE_OPTIONS = [
  {
    value: REALTIME_FEED_SOURCE.SQS,
    label: "Real time via SQS",
    hint: "Recommended. EventBridge forwards risky calls to a queue within seconds.",
  },
  {
    value: REALTIME_FEED_SOURCE.LOOKUP,
    label: "CloudTrail lookup",
    hint: "No setup. Reads CloudTrail LookupEvents, a few minutes behind.",
  },
] as const;

interface FeedSectionProps extends SectionBaseProps {
  feed: RealtimeFeed | null;
}

export function FeedSection({ feed, ...section }: FeedSectionProps) {
  const status = feed ? feedStatusBadge(feed.status) : null;
  return (
    <ConfigSectionCard
      id="feed"
      number={section.number}
      title="Event feed"
      description="Where Prowler reads the account's CloudTrail activity from."
      summary={feedSummary(feed)}
      state={section.state}
      required={section.required}
      open={section.open}
      onOpen={section.onOpen}
      badge={status ? <RealtimeBadge descriptor={status} /> : undefined}
    >
      <FeedForm feed={feed} {...section} />
    </ConfigSectionCard>
  );
}

function FeedForm({
  feed,
  providerId,
  canManage,
  onClose,
  onSaved,
}: FeedSectionProps) {
  const router = useRouter();
  const [checking, setChecking] = useState(false);
  const form = useForm<FeedFormValues>({
    resolver: zodResolver(feedFormSchema),
    defaultValues: feedFormDefaults(feed),
  });
  const source = useWatch({ control: form.control, name: "source" });
  const { errors, isSubmitting } = useFormState({ control: form.control });

  const submit = async (values: FeedFormValues) => {
    const result = await saveRealtimeFeed({
      providerId,
      feedId: feed?.id,
      feed: toFeedInput(values),
    });
    if (!result.ok) {
      reportSaveFailure(result, form.setError, FEED_FIELDS, "Feed not saved");
      return;
    }
    toast({ title: "Event feed saved" });
    onSaved();
  };

  const checkNow = async () => {
    if (!feed) return;
    setChecking(true);
    const result = await pollRealtimeFeed(feed.id);
    setChecking(false);
    if (!result.ok) {
      toast({
        variant: "destructive",
        title: "Check not started",
        description: result.error,
      });
      return;
    }
    toast({
      title: "Check started",
      description: "The feed status updates in a few seconds.",
    });
    router.refresh();
    window.setTimeout(() => router.refresh(), RECHECK_DELAY_MS);
  };

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate>
      <fieldset
        disabled={!canManage}
        className="flex flex-col gap-5 px-[18px] py-4"
      >
        <legend className="sr-only">Event feed</legend>
        {feed && (
          <div className="bg-bg-neutral-tertiary border-border-neutral-secondary flex flex-wrap items-center gap-x-6 gap-y-2 rounded-lg border px-4 py-3 text-sm">
            <span className="flex flex-col">
              <span className="text-text-neutral-tertiary text-xs">Source</span>
              {feed.queue_url ? "Real time via SQS" : "CloudTrail lookup"}
            </span>
            <span className="flex flex-col">
              <span className="text-text-neutral-tertiary text-xs">
                Last check
              </span>
              {formatRelativeTime(feed.last_polled_at)}
            </span>
            <span className="flex flex-col">
              <span className="text-text-neutral-tertiary text-xs">
                Last event
              </span>
              {formatRelativeTime(feed.last_event_at)}
            </span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="ml-auto"
              onClick={checkNow}
              disabled={checking || !canManage}
            >
              <RefreshCw
                aria-hidden
                className={cn(checking && "animate-spin")}
              />
              Check now
            </Button>
          </div>
        )}
        {feed?.last_error && (
          <Alert variant="error">
            <AlertTitle>The last check failed</AlertTitle>
            <AlertDescription>{feed.last_error}</AlertDescription>
          </Alert>
        )}

        <Controller
          control={form.control}
          name="source"
          render={({ field }) => (
            <RadioGroup
              value={field.value}
              onValueChange={field.onChange}
              aria-label="Feed source"
              className="grid gap-3 md:grid-cols-2"
            >
              {SOURCE_OPTIONS.map((option) => (
                <label
                  key={option.value}
                  className={cn(
                    "border-border-input-primary bg-bg-input-primary flex cursor-pointer items-start gap-3 rounded-lg border px-4 py-3",
                    field.value === option.value && "border-button-primary",
                  )}
                >
                  <RadioGroupItem value={option.value} className="mt-0.5" />
                  <span className="flex flex-col gap-0.5">
                    <span className="text-text-neutral-primary text-sm font-medium">
                      {option.label}
                    </span>
                    <span className="text-text-neutral-tertiary text-xs">
                      {option.hint}
                    </span>
                  </span>
                </label>
              ))}
            </RadioGroup>
          )}
        />

        {source === REALTIME_FEED_SOURCE.SQS ? (
          <>
            <TemplateGuide
              cloudformation={FEED_CLOUDFORMATION}
              terraform={FEED_TERRAFORM}
              steps={[
                "Deploy the template in one region of this AWS account. IAM and S3 account events arrive in us-east-1.",
                "Copy the QueueUrl output of the stack.",
                "Paste it below and save.",
              ]}
            />
            <Field>
              <FieldLabel htmlFor="feed-queue-url">SQS queue URL</FieldLabel>
              <Input
                id="feed-queue-url"
                placeholder="https://sqs.us-east-1.amazonaws.com/123456789012/prowler-realtime-events"
                aria-invalid={Boolean(errors.queue_url)}
                {...form.register("queue_url", {
                  onChange: (event: { target: { value: string } }) => {
                    const region = regionFromQueueUrl(event.target.value);
                    if (region) form.setValue("region", region);
                  },
                })}
              />
              {errors.queue_url && (
                <FieldError>{errors.queue_url.message}</FieldError>
              )}
            </Field>
          </>
        ) : (
          <Field className="max-w-xs">
            <FieldLabel htmlFor="feed-region">Main region</FieldLabel>
            <Input
              id="feed-region"
              aria-invalid={Boolean(errors.region)}
              {...form.register("region")}
            />
            <span className="text-text-neutral-tertiary text-xs">
              Prowler also reads us-east-1, where global events arrive.
            </span>
            {errors.region && <FieldError>{errors.region.message}</FieldError>}
          </Field>
        )}
      </fieldset>
      <SectionFooter
        onCancel={onClose}
        submitLabel={feed ? "Save" : "Save and continue"}
        pending={isSubmitting}
        disabled={!canManage}
      />
    </form>
  );
}
