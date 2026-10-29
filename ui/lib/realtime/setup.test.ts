import { describe, expect, it } from "vitest";

import type { RealtimeSetupPayload } from "@/types/realtime";

import {
  canEnterStep,
  nextStepAfter,
  resumeStep,
  SETUP_STEP,
  SETUP_STEP_ORDER,
  stepBefore,
  stepProgress,
  WIZARD_DEFAULT_POLICY,
} from "./setup";

const setup = (
  overrides: Partial<RealtimeSetupPayload> = {},
  done: Record<string, boolean> = {},
): RealtimeSetupPayload => ({
  activated: false,
  next_step: "feed",
  steps: [
    { id: "feed", required: true, done: done.feed ?? false, detail: null },
    {
      id: "enforcement",
      required: true,
      done: done.enforcement ?? false,
      detail: null,
    },
    { id: "remediation", required: false, done: false, detail: null },
    { id: "alerts", required: false, done: false, detail: null },
    { id: "cost", required: false, done: false, detail: null },
    { id: "activate", required: true, done: false, detail: null },
  ],
  ...overrides,
});

describe("setup steps", () => {
  it("runs account, feed, enforcement, remediation, alerts, cost, activate", () => {
    expect(SETUP_STEP_ORDER).toEqual([
      "account",
      "feed",
      "enforcement",
      "remediation",
      "alerts",
      "cost",
      "activate",
    ]);
    expect(nextStepAfter(SETUP_STEP.COST)).toBe(SETUP_STEP.ACTIVATE);
    expect(nextStepAfter(SETUP_STEP.ACTIVATE)).toBeNull();
    expect(stepBefore(SETUP_STEP.ACCOUNT)).toBeNull();
    expect(stepBefore(SETUP_STEP.FEED)).toBe(SETUP_STEP.ACCOUNT);
  });

  it("resumes at the step the API names", () => {
    expect(resumeStep(setup({ next_step: "enforcement" }))).toBe("enforcement");
    expect(resumeStep(setup({ next_step: "activate" }))).toBe("activate");
  });

  it("falls back to the first required step that is not done", () => {
    expect(resumeStep(setup({ next_step: null }, { feed: true }))).toBe(
      "enforcement",
    );
    expect(
      resumeStep(setup({ next_step: null }, { feed: true, enforcement: true })),
    ).toBe("activate");
  });

  it("has nothing to resume once activated", () => {
    expect(resumeStep(setup({ activated: true, next_step: null }))).toBeNull();
  });

  it("opens a step only when every required step before it is done", () => {
    expect(canEnterStep("feed", undefined)).toBe(true);
    expect(canEnterStep("enforcement", setup())).toBe(false);
    expect(canEnterStep("enforcement", setup({}, { feed: true }))).toBe(true);
    expect(canEnterStep("alerts", setup({}, { feed: true }))).toBe(false);
    expect(
      canEnterStep("alerts", setup({}, { feed: true, enforcement: true })),
    ).toBe(true);
    // Optional steps never block the review.
    expect(
      canEnterStep("activate", setup({}, { feed: true, enforcement: true })),
    ).toBe(true);
  });

  it("reports a step's progress, the account step being always done", () => {
    expect(stepProgress("account", undefined)).toMatchObject({ done: true });
    expect(stepProgress("feed", setup({}, { feed: true }))).toMatchObject({
      required: true,
      done: true,
    });
    expect(stepProgress("cost", setup())).toMatchObject({ required: false });
  });

  it("starts a policy switched off, in monitor mode, with dry run on", () => {
    expect(WIZARD_DEFAULT_POLICY).toMatchObject({
      enabled: false,
      mode: "monitor",
      dry_run: true,
    });
    expect(WIZARD_DEFAULT_POLICY.notifications.slack.enabled).toBe(false);
  });
});
