import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Survey } from "posthog-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { clampSidePanelWidth } from "@/lib/ui-layout";

type SurveyCallback = (surveys: Survey[]) => void;

const mocks = vi.hoisted(() => ({
  isCloud: vi.fn(),
  useRuntimeConfig: vi.fn(),
  init: vi.fn(),
  onSurveysLoaded: vi.fn(),
  capture: vi.fn(),
  moduleLoaded: vi.fn(),
  pathname: "/",
  isPushViewport: false,
  // Mirrors the singleton's `__loaded` flag: true when a PostHog instance
  // already exists (as on Prowler Cloud, initialized in app/providers.tsx).
  loaded: false,
}));

vi.mock("@/lib/shared/env", () => ({ isCloud: mocks.isCloud }));
vi.mock("@/hooks/use-runtime-config", () => ({
  useRuntimeConfig: mocks.useRuntimeConfig,
}));
vi.mock("@/hooks/use-media-query", () => ({
  useMediaQuery: () => mocks.isPushViewport,
}));
vi.mock("next/navigation", () => ({
  usePathname: () => mocks.pathname,
}));
vi.mock("posthog-js", () => {
  mocks.moduleLoaded();
  return {
    default: {
      get __loaded() {
        return mocks.loaded;
      },
      init: mocks.init,
      onSurveysLoaded: mocks.onSurveysLoaded,
      capture: mocks.capture,
    },
  };
});

const POSTHOG_KEY = "phc_key";
const GLOBAL_STYLES = readFileSync(
  resolve(process.cwd(), "styles/globals.css"),
  "utf8",
);

const SURVEY_FIXTURE = {
  id: "survey-123",
  name: "Prowler Feedback",
  type: "api",
  questions: [
    {
      id: "q-1",
      type: "open",
      question: "What could we do better?",
      description:
        "Is there anything we could do to make your experience better?",
    },
  ],
  appearance: {
    placeholder: "Type your answer here",
    submitButtonText: "Submit answer",
    thankYouMessageHeader: "Thanks for the feedback!",
    thankYouMessageDescription: "The Prowler team reads every response.",
  },
} as unknown as Survey;

// Feed the given surveys to the component through the posthog callback the way
// the real SDK does once the definitions have loaded.
const provideSurveys = (surveys: Survey[]): void => {
  mocks.onSurveysLoaded.mockImplementation((callback: SurveyCallback) => {
    callback(surveys);
    return () => {};
  });
};

// Pre-evaluating the lazy chunk keeps findBy* queries from racing module
// evaluation under full-suite load; guard tests that assert the chunk is never
// touched opt out via preloadRuntime: false.
const renderSurvey = async ({ preloadRuntime = true } = {}) => {
  if (preloadRuntime) await import("./runtime-feedback-survey");
  const { FeedbackSurvey } = await import("./feedback-survey");
  return render(<FeedbackSurvey />);
};

describe("FeedbackSurvey", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.resetAllMocks();
    mocks.loaded = false;
    mocks.pathname = "/";
    mocks.isPushViewport = false;
    localStorage.clear();
    mocks.isCloud.mockReturnValue(true);
    mocks.useRuntimeConfig.mockReturnValue({
      cloudEnabled: true,
      posthogEnabled: true,
      posthogKey: POSTHOG_KEY,
      posthogHost: "https://eu.posthog.com",
    });
    provideSurveys([SURVEY_FIXTURE]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("renders an accessible icon-only circular feedback trigger", async () => {
    // When
    await renderSurvey();

    // Then
    const trigger = await screen.findByRole("button", {
      name: "Give feedback",
    });
    expect(trigger).toBeVisible();
    expect(trigger).toHaveAccessibleName("Give feedback");
    expect(trigger).not.toHaveTextContent("Feedback");
    expect(trigger.querySelector("svg")).toBeInTheDocument();
    expect(trigger).toHaveClass("rounded-full", "size-10");
  });

  it("activates feedback clearance only on the semantic main page scroller", async () => {
    // When
    await renderSurvey();

    // Then
    const trigger = await screen.findByRole("button", {
      name: "Give feedback",
    });
    expect(trigger).toHaveAttribute("data-feedback-survey-trigger");
    expect(GLOBAL_STYLES).toMatch(
      /body:has\(\[data-feedback-survey-trigger\]\)\s+main\[data-responsive-container\]\s*{\s*@apply pb-36;\s*}/,
    );
    expect(GLOBAL_STYLES).not.toMatch(
      /body:has\(\[data-feedback-survey-trigger\]\)\s+\[data-responsive-container\]\s*{/,
    );
  });

  it("keeps the normal right gutter above page content when the side panel is closed", async () => {
    // Given
    mocks.isPushViewport = true;

    // When
    await renderSurvey();

    // Then
    const trigger = await screen.findByRole("button", {
      name: "Give feedback",
    });
    expect(trigger).toHaveClass("right-6", "z-50");
    expect(trigger.style.right).toBe("");
  });

  it("moves left by the clamped panel width on push viewports", async () => {
    // Given - persisted widths are consumed defensively, just like MainLayout.
    const persistedWidth = 2000;
    vi.stubGlobal("innerWidth", 1200);
    mocks.isPushViewport = true;
    const { useSidePanelStore } = await import("@/store/side-panel");
    useSidePanelStore.setState({
      isOpen: true,
      width: persistedWidth,
    });

    // When
    await renderSurvey();

    // Then
    const trigger = await screen.findByRole("button", {
      name: "Give feedback",
    });
    await waitFor(() =>
      expect(trigger).toHaveStyle({
        right: `${clampSidePanelWidth(persistedWidth) + 24}px`,
      }),
    );
    expect(trigger).toHaveClass("transition-[right,transform]", "duration-200");
  });

  it("keeps the normal gutter on Lighthouse when stale state says the absent panel is open", async () => {
    // Given
    mocks.pathname = "/lighthouse";
    mocks.isPushViewport = true;
    const { useSidePanelStore } = await import("@/store/side-panel");
    useSidePanelStore.setState({ isOpen: true, width: 720 });

    // When
    await renderSurvey();

    // Then
    const trigger = await screen.findByRole("button", {
      name: "Give feedback",
    });
    expect(trigger).toBeVisible();
    expect(trigger.style.right).toBe("");
  });

  it("hides the feedback trigger when the side panel overlays on mobile", async () => {
    // Given
    mocks.isPushViewport = false;
    const { useSidePanelStore } = await import("@/store/side-panel");
    useSidePanelStore.setState({ isOpen: true, width: 720 });

    // When
    await renderSurvey();

    // Then
    await waitFor(() => expect(mocks.onSurveysLoaded).toHaveBeenCalled());
    expect(
      screen.queryByRole("button", { name: "Give feedback" }),
    ).not.toBeInTheDocument();
  });

  it("keeps the feedback form closed after the mobile side panel closes", async () => {
    // Given
    mocks.isPushViewport = false;
    const user = userEvent.setup();
    const { useSidePanelStore } = await import("@/store/side-panel");
    useSidePanelStore.setState({ isOpen: false });
    await renderSurvey();
    await user.click(
      await screen.findByRole("button", { name: "Give feedback" }),
    );
    expect(
      await screen.findByRole("heading", { name: "What could we do better?" }),
    ).toBeVisible();

    // When
    act(() => useSidePanelStore.setState({ isOpen: true }));
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: "Give feedback" }),
      ).not.toBeInTheDocument(),
    );
    act(() => useSidePanelStore.setState({ isOpen: false }));

    // Then
    expect(
      await screen.findByRole("button", { name: "Give feedback" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "What could we do better?" }),
    ).not.toBeInTheDocument();
  });

  it("ignores a same-name non-API survey and selects the API survey", async () => {
    // Given - PostHog can return multiple survey types with the same name.
    const popoverSurvey = {
      ...SURVEY_FIXTURE,
      id: "survey-popover",
      type: "popover",
      questions: [
        {
          id: "q-popover",
          type: "open",
          question: "This popover must not render",
        },
      ],
    } as unknown as Survey;
    provideSurveys([popoverSurvey, SURVEY_FIXTURE]);
    const user = userEvent.setup();

    // When
    await renderSurvey();
    await user.click(
      await screen.findByRole("button", { name: "Give feedback" }),
    );

    // Then
    expect(
      await screen.findByRole("heading", { name: "What could we do better?" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "This popover must not render" }),
    ).not.toBeInTheDocument();
  });

  it("opens a visible feedback form with the fetched question, description, placeholder, and submit copy", async () => {
    // Given
    const user = userEvent.setup();
    await renderSurvey();
    const trigger = await screen.findByRole("button", {
      name: "Give feedback",
    });

    // Then - the form is not present until the user opens it
    expect(
      screen.queryByRole("heading", { name: "What could we do better?" }),
    ).not.toBeInTheDocument();

    // When
    await user.click(trigger);

    // Then - the user actually sees the survey copy from the definition
    expect(
      await screen.findByRole("heading", { name: "What could we do better?" }),
    ).toBeVisible();
    expect(
      screen.getByText(
        "Is there anything we could do to make your experience better?",
      ),
    ).toBeVisible();
    const input = screen.getByPlaceholderText("Type your answer here");
    expect(input).toBeVisible();
    expect(screen.getByRole("button", { name: "Submit answer" })).toBeVisible();
  });

  it("captures 'survey shown' when the form opens", async () => {
    // Given
    const user = userEvent.setup();
    await renderSurvey();
    const trigger = await screen.findByRole("button", {
      name: "Give feedback",
    });

    // When
    await user.click(trigger);

    // Then
    await waitFor(() =>
      expect(mocks.capture).toHaveBeenCalledWith("survey shown", {
        $survey_id: "survey-123",
        $survey_name: "Prowler Feedback",
      }),
    );
  });

  it("captures 'survey sent' with modern and legacy response keys and then thanks the user", async () => {
    // Given
    const user = userEvent.setup();
    await renderSurvey();
    await user.click(
      await screen.findByRole("button", { name: "Give feedback" }),
    );
    await user.type(
      screen.getByPlaceholderText("Type your answer here"),
      "Add dark mode",
    );

    // When
    await user.click(screen.getByRole("button", { name: "Submit answer" }));

    // Then - the capture carries the survey identity, per-question payload, and
    // BOTH the modern per-question key and the legacy first-question key.
    await waitFor(() =>
      expect(mocks.capture).toHaveBeenCalledWith("survey sent", {
        $survey_id: "survey-123",
        $survey_name: "Prowler Feedback",
        $survey_questions: [
          {
            id: "q-1",
            question: "What could we do better?",
            response: "Add dark mode",
          },
        ],
        "$survey_response_q-1": "Add dark mode",
        $survey_response: "Add dark mode",
      }),
    );

    // Then - the user sees the thank-you copy from the definition
    expect(await screen.findByText("Thanks for the feedback!")).toBeVisible();
    expect(
      screen.getByText("The Prowler team reads every response."),
    ).toBeVisible();
  });

  it("captures 'survey dismissed' when the form is closed without submitting", async () => {
    // Given
    const user = userEvent.setup();
    await renderSurvey();
    await user.click(
      await screen.findByRole("button", { name: "Give feedback" }),
    );
    await screen.findByRole("heading", { name: "What could we do better?" });

    // When - the user closes the popover without answering
    await user.keyboard("{Escape}");

    // Then
    await waitFor(() =>
      expect(mocks.capture).toHaveBeenCalledWith("survey dismissed", {
        $survey_id: "survey-123",
        $survey_name: "Prowler Feedback",
      }),
    );
  });

  it("does not dismiss after a successful submit when the form is closed", async () => {
    // Given
    const user = userEvent.setup();
    await renderSurvey();
    await user.click(
      await screen.findByRole("button", { name: "Give feedback" }),
    );
    await user.type(
      screen.getByPlaceholderText("Type your answer here"),
      "Great tool",
    );
    await user.click(screen.getByRole("button", { name: "Submit answer" }));
    await screen.findByText("Thanks for the feedback!");

    // When - the user closes the thank-you popover
    await user.keyboard("{Escape}");

    // Then - a submitted survey is never also reported as dismissed
    await waitFor(() =>
      expect(mocks.capture).toHaveBeenCalledWith(
        "survey sent",
        expect.anything(),
      ),
    );
    expect(mocks.capture).not.toHaveBeenCalledWith(
      "survey dismissed",
      expect.anything(),
    );
  });

  it("initializes PostHog once with the runtime config, then loads surveys, when Cloud with a key and host and no existing instance", async () => {
    // Given - no PostHog instance exists yet (self-hosted opt-in path). Init is
    // deferred to this component effect (post-hydration) to avoid a hydration
    // mismatch, using the runtime public config island.
    mocks.loaded = false;

    // When
    await renderSurvey();

    // Then
    await waitFor(() => expect(mocks.init).toHaveBeenCalledTimes(1));
    expect(mocks.init.mock.calls[0][0]).toBe(POSTHOG_KEY);
    expect(mocks.init.mock.calls[0][1]).toMatchObject({
      api_host: "https://eu.posthog.com",
      ui_host: "https://eu.posthog.com",
      autocapture: false,
      capture_pageview: false,
      capture_pageleave: false,
    });
    await waitFor(() => expect(mocks.onSurveysLoaded).toHaveBeenCalled());
  });

  it("consumes the already-initialized Cloud instance without re-initializing", async () => {
    // Given - on Prowler Cloud the singleton is already initialized
    // (app/providers.tsx), so __loaded is true.
    mocks.loaded = true;

    // When
    await renderSurvey();

    // Then - it reuses Cloud's instance: no re-init, but surveys still load and
    // the trigger renders.
    await waitFor(() => expect(mocks.onSurveysLoaded).toHaveBeenCalled());
    expect(mocks.init).not.toHaveBeenCalled();
    expect(
      await screen.findByRole("button", { name: "Give feedback" }),
    ).toBeVisible();
  });

  it("does not initialize or load surveys when the runtime config is empty", async () => {
    // Given - the runtime config island has not provided PostHog settings
    mocks.loaded = false;
    mocks.useRuntimeConfig.mockReturnValue({
      cloudEnabled: false,
      posthogEnabled: false,
      posthogKey: null,
      posthogHost: null,
    });

    // When
    const view = await renderSurvey({ preloadRuntime: false });

    // Then - no init, no survey fetch, nothing rendered
    expect(mocks.init).not.toHaveBeenCalled();
    expect(mocks.onSurveysLoaded).not.toHaveBeenCalled();
    expect(mocks.moduleLoaded).not.toHaveBeenCalled();
    expect(view.container).toBeEmptyDOMElement();
  });

  it("renders nothing and touches no PostHog surface when PostHog is disabled, even with a key and host present", async () => {
    // Given - the integration is off with a stale key/host still present
    mocks.loaded = false;
    mocks.useRuntimeConfig.mockReturnValue({
      cloudEnabled: true,
      posthogEnabled: false,
      posthogKey: POSTHOG_KEY,
      posthogHost: "https://eu.posthog.com",
    });

    // When
    const view = await renderSurvey({ preloadRuntime: false });

    // Then
    expect(view.container).toBeEmptyDOMElement();
    expect(
      screen.queryByRole("button", { name: "Give feedback" }),
    ).not.toBeInTheDocument();
    expect(mocks.init).not.toHaveBeenCalled();
    expect(mocks.onSurveysLoaded).not.toHaveBeenCalled();
    expect(mocks.capture).not.toHaveBeenCalled();
    expect(mocks.moduleLoaded).not.toHaveBeenCalled();
  });

  it("renders nothing and touches no PostHog surface when not Cloud, even with a survey and key present", async () => {
    // Given - OSS: isCloud() is the primary guard, even with a key and instance
    mocks.isCloud.mockReturnValue(false);
    mocks.loaded = true;
    provideSurveys([SURVEY_FIXTURE]);

    // When
    const view = await renderSurvey({ preloadRuntime: false });

    // Then - no init, no trigger, no survey fetch, no capture, regardless of config
    expect(view.container).toBeEmptyDOMElement();
    expect(
      screen.queryByRole("button", { name: "Give feedback" }),
    ).not.toBeInTheDocument();
    expect(mocks.init).not.toHaveBeenCalled();
    expect(mocks.onSurveysLoaded).not.toHaveBeenCalled();
    expect(mocks.capture).not.toHaveBeenCalled();
    expect(mocks.moduleLoaded).not.toHaveBeenCalled();
  });

  it("renders nothing when Cloud but the named survey is not available", async () => {
    // Given
    provideSurveys([]);

    // When
    const view = await renderSurvey();

    // Then
    await waitFor(() => expect(mocks.onSurveysLoaded).toHaveBeenCalled());
    expect(view.container).toBeEmptyDOMElement();
    expect(mocks.capture).not.toHaveBeenCalled();
  });

  it("renders nothing and never crashes when the matched survey has no questions", async () => {
    // Given - a definition with an empty questions array (regression: submit
    // used to read questions[0].question unguarded and could crash).
    const questionlessSurvey = {
      ...SURVEY_FIXTURE,
      questions: [],
    } as unknown as Survey;
    provideSurveys([questionlessSurvey]);

    // When
    const view = await renderSurvey();

    // Then - no trigger renders, so the form (and its question access) is
    // unreachable: nothing to interact with, nothing throws.
    await waitFor(() => expect(mocks.onSurveysLoaded).toHaveBeenCalled());
    expect(view.container).toBeEmptyDOMElement();
    expect(
      screen.queryByRole("button", { name: "Give feedback" }),
    ).not.toBeInTheDocument();
    expect(mocks.capture).not.toHaveBeenCalled();
  });

  it("renders nothing when the first question is not an open-text question", async () => {
    // Given - an editor changed the question type in the PostHog dashboard to a
    // non-open kind; the free-text form only matches `open`.
    const ratingSurvey = {
      ...SURVEY_FIXTURE,
      questions: [
        {
          id: "q-1",
          type: "rating",
          question: "How would you rate Prowler?",
          display: "number",
          scale: 5,
          lowerBoundLabel: "Bad",
          upperBoundLabel: "Great",
        },
      ],
    } as unknown as Survey;
    provideSurveys([ratingSurvey]);

    // When
    const view = await renderSurvey();

    // Then - feature safely off: no trigger, no malformed response path
    await waitFor(() => expect(mocks.onSurveysLoaded).toHaveBeenCalled());
    expect(view.container).toBeEmptyDOMElement();
    expect(
      screen.queryByRole("button", { name: "Give feedback" }),
    ).not.toBeInTheDocument();
    expect(mocks.capture).not.toHaveBeenCalled();
  });
});
