"use client";

import { FlaskConical } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { getScan } from "@/actions/scans";
import {
  Badge,
  Button,
  Card,
  CardContent,
  Progress,
} from "@/components/shadcn";
import { toast } from "@/components/shadcn/toast";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { WIZARD_OPEN_SOURCE } from "@/lib/provider-funnel/provider-funnel-events";
import { buildAddProviderHref } from "@/lib/providers-navigation";
import {
  dispatchSamplePreview,
  SAMPLE_PREVIEW_CTA,
  SAMPLE_PREVIEW_STEP,
  type SamplePreviewCta,
  type SamplePreviewPage,
} from "@/lib/sample-preview/sample-preview-events";
import {
  SAMPLE_PREVIEW_STAGE,
  type SamplePreviewActive,
  type SamplePreviewStage,
} from "@/lib/sample-preview/sample-preview-state";
import { LAUNCH_SCAN_HREF } from "@/lib/scans-navigation";
import { SCAN_STATES } from "@/types/attack-paths";
import { SCAN_JOBS_TAB } from "@/types/scans";

export const SAMPLE_PREVIEW_POLL_INTERVAL_MS = 15_000;

interface StageContent {
  title: string;
  description: string;
  cta: SamplePreviewCta;
  ctaLabel: string;
  href: string;
}

const STAGE_CONTENT = {
  [SAMPLE_PREVIEW_STAGE.NO_PROVIDER]: {
    title: "You are exploring sample data",
    description:
      "It comes from a demo AWS account. Connect your cloud account to see your own findings here.",
    cta: SAMPLE_PREVIEW_CTA.ADD_PROVIDER,
    ctaLabel: "Add Provider",
    href: buildAddProviderHref(WIZARD_OPEN_SOURCE.SAMPLE_PREVIEW),
  },
  [SAMPLE_PREVIEW_STAGE.NO_SCAN]: {
    title: "You are exploring sample data",
    description:
      "It comes from a demo AWS account. Launch a scan to see your own findings here.",
    cta: SAMPLE_PREVIEW_CTA.LAUNCH_SCAN,
    ctaLabel: "Launch Scan",
    href: LAUNCH_SCAN_HREF,
  },
  [SAMPLE_PREVIEW_STAGE.SCAN_RUNNING]: {
    title: "Your first scan is running",
    description:
      "Meanwhile, explore sample data from a demo AWS account. Your results replace it as soon as the scan finishes.",
    cta: SAMPLE_PREVIEW_CTA.VIEW_SCAN,
    ctaLabel: "View Scan",
    href: `/scans?tab=${SCAN_JOBS_TAB.ACTIVE}`,
  },
} as const satisfies Record<SamplePreviewStage, StageContent>;

interface SamplePreviewBannerProps {
  state: SamplePreviewActive;
  page: SamplePreviewPage;
}

export function SamplePreviewBanner({ state, page }: SamplePreviewBannerProps) {
  // A new stage or scan after a refresh restarts the tracking and polling.
  return (
    <SamplePreviewBannerContent
      key={`${state.stage}-${state.runningScan?.id ?? "none"}`}
      state={state}
      page={page}
    />
  );
}

function SamplePreviewBannerContent({ state, page }: SamplePreviewBannerProps) {
  const router = useRouter();
  const { stage, runningScan } = state;
  // Local state needed: polling updates the progress between server renders.
  const [progress, setProgress] = useState(runningScan?.progress ?? 0);
  const content = STAGE_CONTENT[stage];

  useMountEffect(() => {
    dispatchSamplePreview({ step: SAMPLE_PREVIEW_STEP.VIEWED, page, stage });

    if (!runningScan) return;

    let stopped = false;
    let inFlight = false;
    const poll = async () => {
      // A slow response must not overwrite a newer one.
      if (inFlight) return;
      inFlight = true;
      const response = await getScan(runningScan.id).finally(() => {
        inFlight = false;
      });
      if (stopped) return;

      // The scan is gone (e.g. its provider was deleted): re-resolve the page.
      if (response?.status === 404) {
        stop();
        router.refresh();
        return;
      }

      const attributes = response?.data?.attributes;
      if (!attributes) return;

      if (attributes.state === SCAN_STATES.COMPLETED) {
        stop();
        dispatchSamplePreview({
          step: SAMPLE_PREVIEW_STEP.EXITED,
          page,
          stage,
        });
        toast({
          title: "Your scan results are ready",
          description: "The sample data has been replaced with your own.",
        });
        router.refresh();
        return;
      }

      if (attributes.state === SCAN_STATES.FAILED) {
        stop();
        router.refresh();
        return;
      }

      setProgress(attributes.progress ?? 0);
    };

    const intervalId = setInterval(poll, SAMPLE_PREVIEW_POLL_INTERVAL_MS);
    function stop() {
      stopped = true;
      clearInterval(intervalId);
    }
    return stop;
  });

  return (
    <Card variant="base" padding="none" className="mb-6">
      <CardContent className="flex flex-col gap-4 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5">
        <div className="flex min-w-0 items-center gap-3">
          <span className="border-border-neutral-tertiary bg-bg-neutral-tertiary flex size-9 shrink-0 items-center justify-center rounded-md border">
            <FlaskConical aria-hidden="true" className="size-5" />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <p className="text-text-neutral-primary text-sm font-medium">
                {content.title}
              </p>
              <Badge variant="info" size="sm">
                Sample data
              </Badge>
            </div>
            <p className="text-text-neutral-secondary text-sm">
              {content.description}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-4">
          {runningScan ? (
            <div className="flex w-40 items-center gap-2">
              <Progress value={progress} aria-label="First scan progress" />
              <span className="text-text-neutral-secondary text-sm tabular-nums">
                {progress}%
              </span>
            </div>
          ) : null}
          <Button
            asChild
            size="sm"
            variant={runningScan ? "outline" : "default"}
          >
            <Link
              href={content.href}
              onClick={() =>
                dispatchSamplePreview({
                  step: SAMPLE_PREVIEW_STEP.CTA_CLICKED,
                  page,
                  stage,
                  cta: content.cta,
                })
              }
            >
              {content.ctaLabel}
            </Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
