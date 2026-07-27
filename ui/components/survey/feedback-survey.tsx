"use client";

import { MessageSquareText } from "lucide-react";
import posthog from "posthog-js";
import type { Survey } from "posthog-js";
import { useEffect, useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/shadcn/popover";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import { isCloud } from "@/lib/shared/env";

// The survey is fetched by NAME so its id, question, and copy stay editable from
// the PostHog dashboard without shipping a UI release. Never hardcode the id.
const SURVEY_NAME = "Prowler Feedback";

// PostHog survey capture protocol (posthog-js core surveys/events):
// - open   -> `survey shown`     { $survey_id, $survey_name }
// - submit -> `survey sent`      { ...ids, $survey_questions, per-question keys }
// - close  -> `survey dismissed` { $survey_id, $survey_name }
const SURVEY_EVENT = {
  SHOWN: "survey shown",
  SENT: "survey sent",
  DISMISSED: "survey dismissed",
} as const;

export function FeedbackSurvey() {
  // Cloud-only is the PRIMARY guard: OSS / self-hosted deployments never fetch
  // surveys, never render UI, and never call posthog.capture.
  const enabled = isCloud();
  const [survey, setSurvey] = useState<Survey | null>(null);
  const [open, setOpen] = useState(false);
  const [response, setResponse] = useState("");
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => {
    if (!isCloud()) return;
    // Consume the shared `posthog` singleton. On Prowler Cloud it is already
    // initialized (app/providers.tsx runs first, so `__loaded` is true) and we
    // reuse that instance. Elsewhere (self-hosted with the build-time public
    // key set) we initialize it here — AFTER hydration — to avoid injecting the
    // surveys/config script before React hydrates. Config mirrors Cloud.
    if (!posthog.__loaded) {
      const key = process.env.NEXT_PUBLIC_POSTHOG_KEY;
      if (!key) return;
      posthog.init(key, {
        api_host:
          process.env.NEXT_PUBLIC_POSTHOG_API_HOST || "https://eu.posthog.com",
        ui_host:
          process.env.NEXT_PUBLIC_POSTHOG_UI_HOST || "https://eu.posthog.com",
        autocapture: false,
        capture_pageview: false,
        capture_pageleave: false,
      });
    }
    // Surveys are not available synchronously on load; onSurveysLoaded fires
    // once the definitions arrive (and returns an unsubscribe).
    return posthog.onSurveysLoaded((surveys) => {
      setSurvey(
        surveys.find(
          (item) => item.name === SURVEY_NAME && item.type === "api",
        ) ?? null,
      );
    });
  }, []);

  const question = survey?.questions?.[0];

  // Render nothing (never crash, never send a malformed response) unless there
  // is a usable OPEN-text question. A survey with no questions, or whose first
  // question type was changed in the PostHog dashboard to a non-open kind
  // (rating/choice/etc.), safely turns the feature off — the free-text form
  // only matches an `open` question.
  if (!enabled || !survey || question?.type !== "open") return null;

  const questionId = question.id ?? "";
  const appearance = survey.appearance;
  const trimmedResponse = response.trim();

  const identity = { $survey_id: survey.id, $survey_name: survey.name };

  const handleOpenChange = (nextOpen: boolean) => {
    setOpen(nextOpen);
    if (nextOpen) {
      setSubmitted(false);
      setResponse("");
      posthog.capture(SURVEY_EVENT.SHOWN, identity);
      return;
    }
    // Closing an unanswered survey is a dismissal; a submitted one is not.
    if (!submitted) posthog.capture(SURVEY_EVENT.DISMISSED, identity);
  };

  const handleSubmit = () => {
    if (!trimmedResponse) return;
    posthog.capture(SURVEY_EVENT.SENT, {
      ...identity,
      $survey_questions: [
        {
          id: questionId,
          question: question.question,
          response: trimmedResponse,
        },
      ],
      // Modern per-question key AND the legacy first-question key, so both the
      // current dashboard and legacy response views resolve the answer.
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
          size="lg"
          className="group ring-button-primary/20 hover:ring-button-primary/30 fixed right-6 bottom-20 z-50 h-12 rounded-full px-5 font-semibold shadow-xl ring-4 shadow-black/20 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-2xl active:translate-y-0 active:scale-[0.98] motion-reduce:transform-none motion-reduce:transition-none"
        >
          <MessageSquareText
            aria-hidden="true"
            className="transition-transform duration-200 group-hover:scale-110 group-hover:-rotate-6 motion-reduce:transform-none motion-reduce:transition-none"
          />
          <span>Feedback</span>
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
