import type { Survey, SurveyQuestion } from "posthog-js";

export const LIGHTHOUSE_FEEDBACK_SURVEY_NAME =
  "Lighthouse Request Outcome Feedback";

export const LIGHTHOUSE_FEEDBACK_RATING = {
  UP: "up",
  DOWN: "down",
} as const;

export type LighthouseFeedbackRating =
  (typeof LIGHTHOUSE_FEEDBACK_RATING)[keyof typeof LIGHTHOUSE_FEEDBACK_RATING];

export const LIGHTHOUSE_FEEDBACK_REASON = {
  STYLE: "Don't like the style",
  INSTRUCTIONS: "Didn't fully follow instructions",
  QUALITY: "Low quality",
  BIAS: "Biased",
  SAFETY_OR_LEGAL: "Safety or legal concern",
  OTHER: "Other",
} as const;

export type LighthouseFeedbackReason =
  (typeof LIGHTHOUSE_FEEDBACK_REASON)[keyof typeof LIGHTHOUSE_FEEDBACK_REASON];

export const LIGHTHOUSE_FEEDBACK_REASONS = Object.values(
  LIGHTHOUSE_FEEDBACK_REASON,
);

export const LIGHTHOUSE_FEEDBACK_DETAILS_MAX_LENGTH = 2000;

interface LighthouseFeedbackQuestion {
  id: string;
  question: string;
}

export interface LighthouseFeedbackSurvey {
  id: string;
  name: string;
  ratingQuestion: LighthouseFeedbackQuestion;
  reasonsQuestion: LighthouseFeedbackQuestion;
  detailsQuestion: LighthouseFeedbackQuestion;
}

interface LighthouseFeedbackSubmission {
  targetMessageId: string;
  rating: LighthouseFeedbackRating;
  submissionId: string;
  reasons?: LighthouseFeedbackReason[];
  details?: string;
}

type LighthouseFeedbackResponse = number | string | LighthouseFeedbackReason[];

interface LighthouseFeedbackQuestionResponse {
  id: string;
  question: string;
  response: LighthouseFeedbackResponse;
}

export interface LighthouseFeedbackSurveyEvent {
  $survey_id: string;
  $survey_name: string;
  $survey_submission_id: string;
  $survey_completed: boolean;
  $ai_trace_id: string;
  $survey_questions: LighthouseFeedbackQuestionResponse[];
  $survey_response: LighthouseFeedbackResponse;
  [responseProperty: `$survey_response_${string}`]: LighthouseFeedbackResponse;
}

export function resolveLighthouseFeedbackSurvey(
  surveys: Survey[],
): LighthouseFeedbackSurvey | null {
  const survey = surveys.find(
    (item) =>
      item.name === LIGHTHOUSE_FEEDBACK_SURVEY_NAME && item.type === "api",
  );
  if (
    !survey ||
    !Array.isArray(survey.questions) ||
    survey.questions.length !== 3
  ) {
    return null;
  }

  const [ratingQuestion, reasonsQuestion, detailsQuestion] = survey.questions;
  if (
    !isRatingQuestion(ratingQuestion) ||
    !isReasonsQuestion(reasonsQuestion) ||
    !isDetailsQuestion(detailsQuestion)
  ) {
    return null;
  }
  if (
    new Set([ratingQuestion.id, reasonsQuestion.id, detailsQuestion.id])
      .size !== 3
  ) {
    return null;
  }

  return {
    id: survey.id,
    name: survey.name,
    ratingQuestion: toFeedbackQuestion(ratingQuestion),
    reasonsQuestion: toFeedbackQuestion(reasonsQuestion),
    detailsQuestion: toFeedbackQuestion(detailsQuestion),
  };
}

export function buildLighthouseFeedbackSurveyEvents(
  survey: LighthouseFeedbackSurvey,
  submission: LighthouseFeedbackSubmission,
): LighthouseFeedbackSurveyEvent[] {
  const ratingResponse =
    submission.rating === LIGHTHOUSE_FEEDBACK_RATING.UP ? 1 : 2;
  const reasons = normalizeReasons(submission.reasons);
  const details = normalizeDetails(submission.details);
  const ratingQuestion = toQuestionResponse(
    survey.ratingQuestion,
    ratingResponse,
  );
  const isNegative = submission.rating === LIGHTHOUSE_FEEDBACK_RATING.DOWN;
  const events = [
    buildSurveyEvent(
      survey,
      submission,
      [ratingQuestion],
      !isNegative || (reasons.length === 0 && !details),
    ),
  ];

  if (isNegative && reasons.length > 0) {
    events.push(
      buildSurveyEvent(
        survey,
        submission,
        [ratingQuestion, toQuestionResponse(survey.reasonsQuestion, reasons)],
        !details,
      ),
    );
  }

  if (isNegative && details) {
    events.push(
      buildSurveyEvent(
        survey,
        submission,
        [
          ratingQuestion,
          ...(reasons.length > 0
            ? [toQuestionResponse(survey.reasonsQuestion, reasons)]
            : []),
          toQuestionResponse(survey.detailsQuestion, details),
        ],
        true,
      ),
    );
  }

  return events;
}

function buildSurveyEvent(
  survey: LighthouseFeedbackSurvey,
  submission: LighthouseFeedbackSubmission,
  questions: LighthouseFeedbackQuestionResponse[],
  completed: boolean,
): LighthouseFeedbackSurveyEvent {
  const latestResponse = questions.at(-1)!;
  const responseProperties: Record<
    `$survey_response_${string}`,
    LighthouseFeedbackResponse
  > = {};
  for (const question of questions) {
    responseProperties[`$survey_response_${question.id}`] = question.response;
  }

  return {
    $survey_id: survey.id,
    $survey_name: survey.name,
    $survey_submission_id: submission.submissionId,
    $survey_completed: completed,
    $ai_trace_id: submission.targetMessageId,
    $survey_questions: questions,
    ...responseProperties,
    $survey_response: latestResponse.response,
  };
}

function toQuestionResponse(
  question: LighthouseFeedbackQuestion,
  response: LighthouseFeedbackResponse,
): LighthouseFeedbackQuestionResponse {
  return { ...question, response };
}

function normalizeReasons(
  reasons: LighthouseFeedbackReason[] | undefined,
): LighthouseFeedbackReason[] {
  const selected = new Set<LighthouseFeedbackReason>();
  for (const reason of reasons ?? []) {
    if (LIGHTHOUSE_FEEDBACK_REASONS.includes(reason)) selected.add(reason);
  }
  return Array.from(selected);
}

function normalizeDetails(details: string | undefined): string | undefined {
  const trimmed = details
    ?.trim()
    .slice(0, LIGHTHOUSE_FEEDBACK_DETAILS_MAX_LENGTH);
  return trimmed || undefined;
}

function isRatingQuestion(
  question: SurveyQuestion | undefined,
): question is SurveyQuestion & { id: string } {
  return (
    hasQuestionIdentity(question) &&
    question.type === "rating" &&
    question.display === "emoji" &&
    question.scale === 2 &&
    question.optional !== true
  );
}

function isReasonsQuestion(
  question: SurveyQuestion | undefined,
): question is SurveyQuestion & { id: string } {
  return (
    hasQuestionIdentity(question) &&
    question.type === "multiple_choice" &&
    question.optional === true &&
    question.choices.length === LIGHTHOUSE_FEEDBACK_REASONS.length &&
    question.choices.every(
      (choice, index) => choice === LIGHTHOUSE_FEEDBACK_REASONS[index],
    )
  );
}

function isDetailsQuestion(
  question: SurveyQuestion | undefined,
): question is SurveyQuestion & { id: string } {
  return (
    hasQuestionIdentity(question) &&
    question.type === "open" &&
    question.optional === true
  );
}

function hasQuestionIdentity(
  question: SurveyQuestion | undefined,
): question is SurveyQuestion & { id: string } {
  return (
    typeof question?.id === "string" &&
    question.id.trim().length > 0 &&
    typeof question.question === "string" &&
    question.question.length > 0
  );
}

function toFeedbackQuestion(question: SurveyQuestion & { id: string }) {
  return { id: question.id, question: question.question };
}
