"use client";

import { MessageSquareText } from "lucide-react";
import { usePathname } from "next/navigation";
import posthogClient from "posthog-js";
import type { Survey } from "posthog-js";
import { useEffect, useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/shadcn/popover";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import { useMediaQuery } from "@/hooks/use-media-query";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { useStore } from "@/hooks/use-store";
import { isLighthouseChatRoute } from "@/lib/lighthouse-routes";
import {
  clampSidePanelWidth,
  SIDE_PANEL_PUSH_MEDIA_QUERY,
} from "@/lib/ui-layout";
import { cn } from "@/lib/utils";
import { useSidePanelStore } from "@/store/side-panel";

const SURVEY_NAME = "Prowler Feedback";
const FEEDBACK_GUTTER_PX = 24;

const SURVEY_EVENT = {
  SHOWN: "survey shown",
  SENT: "survey sent",
  DISMISSED: "survey dismissed",
} as const;

interface RuntimeFeedbackSurveyProps {
  posthogKey: string;
  posthogHost: string;
}

export default function RuntimeFeedbackSurvey({
  posthogKey,
  posthogHost,
}: RuntimeFeedbackSurveyProps) {
  const pathname = usePathname();
  const [survey, setSurvey] = useState<Survey | null>(null);
  const [open, setOpen] = useState(false);
  const [response, setResponse] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const sidePanelOpen = useStore(useSidePanelStore, (state) => state.isOpen);
  const sidePanelWidth = useStore(useSidePanelStore, (state) => state.width);
  const sidePanelResizing = useStore(
    useSidePanelStore,
    (state) => state.isResizing,
  );
  const isPushViewport = useMediaQuery(SIDE_PANEL_PUSH_MEDIA_QUERY);
  const sidePanelVisible =
    Boolean(sidePanelOpen) && !isLighthouseChatRoute(pathname);

  useMountEffect(() => {
    if (!posthogClient.__loaded) {
      posthogClient.init(posthogKey, {
        api_host: posthogHost,
        ui_host: posthogHost,
        autocapture: false,
        capture_pageview: false,
        capture_pageleave: false,
      });
    }

    return posthogClient.onSurveysLoaded((surveys) => {
      setSurvey(
        surveys.find(
          (item) => item.name === SURVEY_NAME && item.type === "api",
        ) ?? null,
      );
    });
  });

  useEffect(() => {
    if (sidePanelVisible && !isPushViewport) setOpen(false);
  }, [sidePanelVisible, isPushViewport]);

  const question = survey?.questions?.[0];
  if (!survey || question?.type !== "open") return null;
  if (sidePanelVisible && !isPushViewport) return null;

  const questionId = question.id ?? "";
  const appearance = survey.appearance;
  const trimmedResponse = response.trim();
  const identity = { $survey_id: survey.id, $survey_name: survey.name };
  const pushedRight =
    sidePanelVisible && sidePanelWidth !== undefined && isPushViewport
      ? clampSidePanelWidth(sidePanelWidth) + FEEDBACK_GUTTER_PX
      : undefined;

  const handleOpenChange = (nextOpen: boolean) => {
    setOpen(nextOpen);
    if (nextOpen) {
      setSubmitted(false);
      setResponse("");
      posthogClient.capture(SURVEY_EVENT.SHOWN, identity);
      return;
    }
    if (!submitted) posthogClient.capture(SURVEY_EVENT.DISMISSED, identity);
  };

  const handleSubmit = () => {
    if (!trimmedResponse) return;
    posthogClient.capture(SURVEY_EVENT.SENT, {
      ...identity,
      $survey_questions: [
        {
          id: questionId,
          question: question.question,
          response: trimmedResponse,
        },
      ],
      [`$survey_response_${questionId}`]: trimmedResponse,
      $survey_response: trimmedResponse,
    });
    setSubmitted(true);
  };

  return (
    <Popover open={open} onOpenChange={handleOpenChange}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          aria-label="Give feedback"
          data-feedback-survey-trigger
          shape="circle"
          size="icon-lg"
          className={cn(
            "group fixed right-6 bottom-20 z-50 transition-[right,transform] duration-200 hover:-translate-y-0.5 active:translate-y-0 active:scale-[0.98] motion-reduce:transform-none motion-reduce:transition-none",
            sidePanelVisible && sidePanelResizing && "transition-none",
          )}
          style={{ right: pushedRight }}
        >
          <MessageSquareText
            aria-hidden="true"
            className="transition-transform duration-200 group-hover:scale-110 group-hover:-rotate-6 motion-reduce:transform-none motion-reduce:transition-none"
          />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="end"
        side="top"
        className="w-[min(92vw,26rem)] p-5"
      >
        {submitted ? (
          <div role="status" aria-live="polite" className="flex flex-col gap-1">
            <h2 className="text-text-neutral-primary text-base font-semibold">
              {appearance?.thankYouMessageHeader ?? "Thanks for the feedback!"}
            </h2>
            {appearance?.thankYouMessageDescription ? (
              <p className="text-text-neutral-secondary text-sm">
                {appearance.thankYouMessageDescription}
              </p>
            ) : null}
          </div>
        ) : (
          <form
            className="flex flex-col gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              handleSubmit();
            }}
          >
            <div className="flex flex-col gap-1">
              <h2 className="text-text-neutral-primary text-base font-semibold">
                {question.question}
              </h2>
              {question.description ? (
                <p className="text-text-neutral-secondary text-sm">
                  {question.description}
                </p>
              ) : null}
            </div>
            <Textarea
              aria-label={question.question}
              placeholder={appearance?.placeholder ?? ""}
              value={response}
              onChange={(event) => setResponse(event.target.value)}
              textareaSize="lg"
              className="min-h-32"
            />
            <Button type="submit" disabled={!trimmedResponse}>
              {appearance?.submitButtonText ?? "Submit"}
            </Button>
          </form>
        )}
      </PopoverContent>
    </Popover>
  );
}
