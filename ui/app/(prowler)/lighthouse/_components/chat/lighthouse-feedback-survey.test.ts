import type { Survey } from "posthog-js";
import { describe, expect, it } from "vitest";

import {
  buildLighthouseFeedbackSurveyEvents,
  LIGHTHOUSE_FEEDBACK_DETAILS_MAX_LENGTH,
  type LighthouseFeedbackReason,
  LIGHTHOUSE_FEEDBACK_REASONS,
  resolveLighthouseFeedbackSurvey,
} from "./lighthouse-feedback-survey";

const SURVEY = {
  id: "survey-123",
  name: "Lighthouse Request Outcome Feedback",
  type: "api",
  questions: [
    {
      id: "rating-question-id",
      type: "rating",
      display: "emoji",
      scale: 2,
      question: "How was this outcome?",
      lowerBoundLabel: "Not helpful",
      upperBoundLabel: "Helpful",
    },
    {
      id: "reasons-question-id",
      type: "multiple_choice",
      optional: true,
      choices: [
        "Don't like the style",
        "Didn't fully follow instructions",
        "Low quality",
        "Biased",
        "Safety or legal concern",
        "Other",
      ],
      question: "What could be improved?",
    },
    {
      id: "details-question-id",
      type: "open",
      optional: true,
      question: "Additional feedback",
    },
  ],
} as unknown as Survey;

describe("Lighthouse outcome feedback survey", () => {
  it("should build one completed rating snapshot for a helpful outcome", () => {
    // Given
    const survey = resolveLighthouseFeedbackSurvey([SURVEY]);
    expect(survey).not.toBeNull();

    // When
    const events = buildLighthouseFeedbackSurveyEvents(survey!, {
      targetMessageId: "message-user-1",
      rating: "up",
      submissionId: "submission-1",
    });

    // Then
    expect(events).toEqual([
      {
        $survey_id: "survey-123",
        $survey_name: "Lighthouse Request Outcome Feedback",
        $survey_submission_id: "submission-1",
        $survey_completed: true,
        $ai_trace_id: "message-user-1",
        $survey_questions: [
          {
            id: "rating-question-id",
            question: "How was this outcome?",
            response: 1,
          },
        ],
        "$survey_response_rating-question-id": 1,
        $survey_response: 1,
      },
    ]);
  });

  it("should emit cumulative snapshots for a negative outcome with optional answers", () => {
    // Given
    const survey = resolveLighthouseFeedbackSurvey([SURVEY]);
    expect(survey).not.toBeNull();

    // When
    const events = buildLighthouseFeedbackSurveyEvents(survey!, {
      targetMessageId: "message-user-1",
      rating: "down",
      reasons: ["Low quality", "Other"],
      details: "  Missing evidence.  ",
      submissionId: "submission-1",
    });

    // Then
    expect(events).toEqual([
      {
        $survey_id: "survey-123",
        $survey_name: "Lighthouse Request Outcome Feedback",
        $survey_submission_id: "submission-1",
        $survey_completed: false,
        $ai_trace_id: "message-user-1",
        $survey_questions: [
          {
            id: "rating-question-id",
            question: "How was this outcome?",
            response: 2,
          },
        ],
        "$survey_response_rating-question-id": 2,
        $survey_response: 2,
      },
      {
        $survey_id: "survey-123",
        $survey_name: "Lighthouse Request Outcome Feedback",
        $survey_submission_id: "submission-1",
        $survey_completed: false,
        $ai_trace_id: "message-user-1",
        $survey_questions: [
          {
            id: "rating-question-id",
            question: "How was this outcome?",
            response: 2,
          },
          {
            id: "reasons-question-id",
            question: "What could be improved?",
            response: ["Low quality", "Other"],
          },
        ],
        "$survey_response_rating-question-id": 2,
        "$survey_response_reasons-question-id": ["Low quality", "Other"],
        $survey_response: ["Low quality", "Other"],
      },
      {
        $survey_id: "survey-123",
        $survey_name: "Lighthouse Request Outcome Feedback",
        $survey_submission_id: "submission-1",
        $survey_completed: true,
        $ai_trace_id: "message-user-1",
        $survey_questions: [
          {
            id: "rating-question-id",
            question: "How was this outcome?",
            response: 2,
          },
          {
            id: "reasons-question-id",
            question: "What could be improved?",
            response: ["Low quality", "Other"],
          },
          {
            id: "details-question-id",
            question: "Additional feedback",
            response: "Missing evidence.",
          },
        ],
        "$survey_response_rating-question-id": 2,
        "$survey_response_reasons-question-id": ["Low quality", "Other"],
        "$survey_response_details-question-id": "Missing evidence.",
        $survey_response: "Missing evidence.",
      },
    ]);
  });

  it("should reject an API survey whose reason choices are not allowlisted", () => {
    // Given
    const invalidSurvey = {
      ...SURVEY,
      questions: [
        SURVEY.questions[0],
        {
          ...SURVEY.questions[1],
          choices: ["Not an allowlisted reason"],
        },
        SURVEY.questions[2],
      ],
    } as unknown as Survey;

    // When
    const survey = resolveLighthouseFeedbackSurvey([invalidSurvey]);

    // Then
    expect(survey).toBeNull();
  });

  it("should reject an API survey whose reasons question has no choices", () => {
    // Given
    const invalidSurvey = {
      ...SURVEY,
      questions: [
        SURVEY.questions[0],
        { ...SURVEY.questions[1], choices: undefined },
        SURVEY.questions[2],
      ],
    } as unknown as Survey;

    // When
    const survey = resolveLighthouseFeedbackSurvey([invalidSurvey]);

    // Then
    expect(survey).toBeNull();
  });

  it("should reject an API survey whose reason choices are not an array", () => {
    // Given
    const invalidSurvey = {
      ...SURVEY,
      questions: [
        SURVEY.questions[0],
        { ...SURVEY.questions[1], choices: "Low quality" },
        SURVEY.questions[2],
      ],
    } as unknown as Survey;

    // When
    const survey = resolveLighthouseFeedbackSurvey([invalidSurvey]);

    // Then
    expect(survey).toBeNull();
  });

  it("should reject an API survey with an optional rating question", () => {
    // Given
    const invalidSurvey = {
      ...SURVEY,
      questions: [
        { ...SURVEY.questions[0], optional: true },
        SURVEY.questions[1],
        SURVEY.questions[2],
      ],
    } as unknown as Survey;

    // When
    const survey = resolveLighthouseFeedbackSurvey([invalidSurvey]);

    // Then
    expect(survey).toBeNull();
  });

  it("should reject an API survey with duplicate question identifiers", () => {
    // Given
    const invalidSurvey = {
      ...SURVEY,
      questions: [
        SURVEY.questions[0],
        { ...SURVEY.questions[1], id: SURVEY.questions[0].id },
        SURVEY.questions[2],
      ],
    } as unknown as Survey;

    // When
    const survey = resolveLighthouseFeedbackSurvey([invalidSurvey]);

    // Then
    expect(survey).toBeNull();
  });

  it.each([
    ["a non-rating type", { ...SURVEY.questions[0], type: "open" }],
    ["a non-emoji display", { ...SURVEY.questions[0], display: "number" }],
    ["a scale other than two", { ...SURVEY.questions[0], scale: 3 }],
  ])("should reject an API survey with %s", (_description, ratingQuestion) => {
    // Given
    const invalidSurvey = {
      ...SURVEY,
      questions: [ratingQuestion, SURVEY.questions[1], SURVEY.questions[2]],
    } as unknown as Survey;

    // When
    const survey = resolveLighthouseFeedbackSurvey([invalidSurvey]);

    // Then
    expect(survey).toBeNull();
  });

  it("should accept a required rating question that explicitly declares optional false", () => {
    // Given
    const surveyWithRequiredRating = {
      ...SURVEY,
      questions: [
        { ...SURVEY.questions[0], optional: false },
        SURVEY.questions[1],
        SURVEY.questions[2],
      ],
    } as unknown as Survey;

    // When
    const survey = resolveLighthouseFeedbackSurvey([surveyWithRequiredRating]);

    // Then
    expect(survey).not.toBeNull();
  });

  it.each([
    ["reasons", 1],
    ["details", 2],
  ])(
    "should reject an API survey with a non-optional %s question",
    (_name, index) => {
      // Given
      const invalidSurvey = {
        ...SURVEY,
        questions: [
          SURVEY.questions[0],
          index === 1
            ? { ...SURVEY.questions[1], optional: false }
            : SURVEY.questions[1],
          index === 2
            ? { ...SURVEY.questions[2], optional: false }
            : SURVEY.questions[2],
        ],
      } as unknown as Survey;

      // When
      const survey = resolveLighthouseFeedbackSurvey([invalidSurvey]);

      // Then
      expect(survey).toBeNull();
    },
  );

  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["blank", " "],
  ])(
    "should reject an API survey with a %s question identifier",
    (_name, id) => {
      // Given
      const invalidSurvey = surveyWithQuestionIds([
        SURVEY.questions[0].id,
        id,
        SURVEY.questions[2].id,
      ]);

      // When
      const survey = resolveLighthouseFeedbackSurvey([invalidSurvey]);

      // Then
      expect(survey).toBeNull();
    },
  );

  it.each([
    [
      "rating and reasons",
      "duplicate-rating-question-id",
      "duplicate-rating-question-id",
      SURVEY.questions[2].id,
    ],
    [
      "rating and details",
      "duplicate-rating-question-id",
      SURVEY.questions[1].id,
      "duplicate-rating-question-id",
    ],
    [
      "reasons and details",
      SURVEY.questions[0].id,
      "duplicate-reasons-question-id",
      "duplicate-reasons-question-id",
    ],
  ])(
    "should reject an API survey with duplicate %s identifiers",
    (_name, ratingId, reasonsId, detailsId) => {
      // Given
      const invalidSurvey = surveyWithQuestionIds([
        ratingId,
        reasonsId,
        detailsId,
      ]);

      // When
      const survey = resolveLighthouseFeedbackSurvey([invalidSurvey]);

      // Then
      expect(survey).toBeNull();
    },
  );

  it("should reject an API survey with reordered reason choices", () => {
    // Given
    const invalidSurvey = {
      ...SURVEY,
      questions: [
        SURVEY.questions[0],
        {
          ...SURVEY.questions[1],
          choices: [...LIGHTHOUSE_FEEDBACK_REASONS].reverse(),
        },
        SURVEY.questions[2],
      ],
    } as unknown as Survey;

    // When
    const survey = resolveLighthouseFeedbackSurvey([invalidSurvey]);

    // Then
    expect(survey).toBeNull();
  });

  it("should deduplicate and allowlist reason responses in their selected order", () => {
    // Given
    const survey = resolveLighthouseFeedbackSurvey([SURVEY]);
    expect(survey).not.toBeNull();

    // When
    const events = buildLighthouseFeedbackSurveyEvents(survey!, {
      targetMessageId: "message-user-1",
      rating: "down",
      reasons: [
        "Other",
        "Low quality",
        "Other",
        "Unrecognized",
      ] as unknown as LighthouseFeedbackReason[],
      submissionId: "submission-1",
    });

    // Then
    expect(events).toHaveLength(2);
    expect(events.at(-1)).toMatchObject({
      $survey_completed: true,
      "$survey_response_reasons-question-id": ["Other", "Low quality"],
    });
  });

  it("should trim and defensively bound detail responses", () => {
    // Given
    const survey = resolveLighthouseFeedbackSurvey([SURVEY]);
    expect(survey).not.toBeNull();
    const details = `  ${"x".repeat(LIGHTHOUSE_FEEDBACK_DETAILS_MAX_LENGTH + 1)}  `;

    // When
    const events = buildLighthouseFeedbackSurveyEvents(survey!, {
      targetMessageId: "message-user-1",
      rating: "down",
      details,
      submissionId: "submission-1",
    });

    // Then
    expect(events).toHaveLength(2);
    expect(events.at(-1)).toMatchObject({
      $survey_completed: true,
      "$survey_response_details-question-id": "x".repeat(
        LIGHTHOUSE_FEEDBACK_DETAILS_MAX_LENGTH,
      ),
    });
  });

  it("should complete a negative submission with reasons only", () => {
    // Given
    const survey = resolveLighthouseFeedbackSurvey([SURVEY]);
    expect(survey).not.toBeNull();

    // When
    const events = buildLighthouseFeedbackSurveyEvents(survey!, {
      targetMessageId: "message-user-1",
      rating: "down",
      reasons: ["Low quality"],
      submissionId: "submission-1",
    });

    // Then
    expect(events.map((event) => event.$survey_completed)).toEqual([
      false,
      true,
    ]);
    expect(events.at(-1)?.$survey_questions).toHaveLength(2);
    expect(events.at(-1)?.$survey_response).toEqual(["Low quality"]);
  });

  it("should complete a negative submission with details only", () => {
    // Given
    const survey = resolveLighthouseFeedbackSurvey([SURVEY]);
    expect(survey).not.toBeNull();

    // When
    const events = buildLighthouseFeedbackSurveyEvents(survey!, {
      targetMessageId: "message-user-1",
      rating: "down",
      details: "Missing evidence",
      submissionId: "submission-1",
    });

    // Then
    expect(events.map((event) => event.$survey_completed)).toEqual([
      false,
      true,
    ]);
    expect(events.at(-1)?.$survey_questions).toHaveLength(2);
    expect(events.at(-1)?.$survey_response).toBe("Missing evidence");
  });
});

function surveyWithQuestionIds(ids: [unknown, unknown, unknown]): Survey {
  return {
    ...SURVEY,
    questions: [
      { ...SURVEY.questions[0], id: ids[0] },
      { ...SURVEY.questions[1], id: ids[1] },
      { ...SURVEY.questions[2], id: ids[2] },
    ],
  } as unknown as Survey;
}
