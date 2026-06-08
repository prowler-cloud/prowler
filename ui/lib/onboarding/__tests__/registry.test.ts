import { describe, expect, it } from "vitest";

import type { TourCompletionStore } from "@/lib/tours/store/tour-completion-store";
import type {
  TourCompletionRecord,
  TourDefinition,
  TourId,
} from "@/lib/tours/tour-types";
import { TOUR_COMPLETION_STATES } from "@/lib/tours/tour-types";

import * as onboardingPublicApi from "../index";
import type { OnboardingContext, OnboardingFlow } from "../onboarding-types";
import {
  getFirstIncompleteFlow,
  getFlowById,
  getOrderedFlows,
  onboardingFlows,
} from "../registry";

// Registry only reads { id, version } from tours, so a flat stub is sufficient.
const buildTour = (id: string, version = 1): TourDefinition => ({
  id,
  version,
  coversFiles: [],
  steps: [],
});

const buildFlow = (
  overrides: Partial<OnboardingFlow> = {},
): OnboardingFlow => ({
  id: overrides.id ?? "flow",
  order: overrides.order ?? 1,
  title: overrides.title ?? "Title",
  description: overrides.description ?? "Description",
  route: overrides.route ?? "/route",
  tour: overrides.tour ?? buildTour(overrides.id ?? "flow"),
  isComplete: overrides.isComplete,
  ownsAutoOpen: overrides.ownsAutoOpen,
});

const completedRecord = (
  tourId: string,
  version = 1,
): TourCompletionRecord => ({
  tourId,
  version,
  state: TOUR_COMPLETION_STATES.COMPLETED,
  completedAt: "2026-01-15T12:00:00.000Z",
});

// In-memory store so getFirstIncompleteFlow is testable without localStorage.
const fakeStore = (
  seed: Record<string, TourCompletionRecord> = {},
): TourCompletionStore => {
  const data = new Map<string, TourCompletionRecord>(Object.entries(seed));
  const key = (id: TourId) => `${id.id}.v${id.version}`;
  return {
    get: (id) => data.get(key(id)) ?? null,
    set: (id, record) => {
      data.set(key(id), record);
    },
    clear: (id) => {
      data.delete(key(id));
    },
  };
};

describe("OnboardingFlow / OnboardingContext types", () => {
  it("compiles a fully-populated OnboardingFlow against the declared contract", () => {
    const ctx: OnboardingContext = { hasProviders: false };
    const flow: OnboardingFlow = {
      id: "add-provider",
      order: 1,
      title: "Add your first provider",
      description: "Connect a cloud account to start scanning.",
      route: "/providers",
      tour: buildTour("add-provider"),
      isComplete: (c: OnboardingContext) => c.hasProviders,
    };

    expect(flow.id).toBe("add-provider");
    expect(flow.order).toBe(1);
    expect(flow.route).toBe("/providers");
    expect(flow.isComplete?.(ctx)).toBe(false);
    expect(flow.isComplete?.({ hasProviders: true })).toBe(true);
  });
});

describe("onboardingFlows (production registry)", () => {
  it("registers the add-provider flow as the first onboarding flow", () => {
    const addProvider = getFlowById("add-provider", onboardingFlows);
    expect(addProvider).toBeDefined();
    expect(addProvider?.order).toBe(1);
    expect(addProvider?.route).toBe("/providers");
    expect(addProvider?.tour.id).toBe("add-provider");
  });

  it("treats add-provider as complete when the context reports providers", () => {
    const addProvider = getFlowById("add-provider", onboardingFlows);
    expect(addProvider?.isComplete?.({ hasProviders: true })).toBe(true);
    expect(addProvider?.isComplete?.({ hasProviders: false })).toBe(false);
  });

  it("registers the view-first-scan flow at order 2 on the scans route", () => {
    const flow = getFlowById("view-first-scan", onboardingFlows);
    expect(flow).toBeDefined();
    expect(flow?.order).toBe(2);
    expect(flow?.route).toBe("/scans");
    expect(flow?.tour.id).toBe("view-first-scan");
  });

  it("registers the explore-findings flow at order 3 on the findings route", () => {
    const flow = getFlowById("explore-findings", onboardingFlows);
    expect(flow).toBeDefined();
    expect(flow?.order).toBe(3);
    expect(flow?.route).toBe("/findings");
    expect(flow?.tour.id).toBe("explore-findings");
  });

  it("registers the view-compliance flow at order 4 on the compliance route", () => {
    const flow = getFlowById("view-compliance", onboardingFlows);
    expect(flow).toBeDefined();
    expect(flow?.order).toBe(4);
    expect(flow?.route).toBe("/compliance");
    expect(flow?.tour.id).toBe("view-compliance");
  });

  it("registers the attack-paths flow at order 5 on the attack-paths route", () => {
    const flow = getFlowById("attack-paths", onboardingFlows);
    expect(flow).toBeDefined();
    expect(flow?.order).toBe(5);
    expect(flow?.route).toBe("/attack-paths");
    expect(flow?.tour.id).toBe("attack-paths");
  });

  it("flags attack-paths with ownsAutoOpen so the shared trigger never drives it", () => {
    // attack-paths page owns its own driver; all other flows must be falsy
    const attackPaths = getFlowById("attack-paths", onboardingFlows);
    expect(attackPaths?.ownsAutoOpen).toBe(true);
    for (const flow of onboardingFlows) {
      if (flow.id === "attack-paths") continue;
      expect(flow.ownsAutoOpen).toBeFalsy();
    }
  });

  it("sets a data requirement hint on the scan-dependent flows only", () => {
    const scanDependent = [
      "explore-findings",
      "view-compliance",
      "attack-paths",
    ];
    const standalone = ["add-provider", "view-first-scan"];
    const expectedHint =
      "This step needs a completed scan to show data. Launch a scan first, or continue anyway.";

    for (const id of scanDependent) {
      const flow = getFlowById(id, onboardingFlows);
      expect(flow?.dataRequirementHint).toBe(expectedHint);
    }
    for (const id of standalone) {
      const flow = getFlowById(id, onboardingFlows);
      expect(flow?.dataRequirementHint).toBeUndefined();
    }
  });

  it("orders the five sequence flows 1..5 by registry order", () => {
    const ordered = getOrderedFlows(onboardingFlows);
    expect(ordered.map((flow) => flow.id)).toEqual([
      "add-provider",
      "view-first-scan",
      "explore-findings",
      "view-compliance",
      "attack-paths",
    ]);
  });
});

describe("public api barrel", () => {
  it("re-exports the registry and gate-decision surface", () => {
    expect(onboardingPublicApi.getOrderedFlows).toBe(getOrderedFlows);
    expect(onboardingPublicApi.getFlowById).toBe(getFlowById);
    expect(onboardingPublicApi.getFirstIncompleteFlow).toBe(
      getFirstIncompleteFlow,
    );
    expect(onboardingPublicApi.onboardingFlows).toBe(onboardingFlows);
    expect(typeof onboardingPublicApi.shouldStartOnboarding).toBe("function");
  });
});

describe("getOrderedFlows", () => {
  it("returns an empty array when the registry has no flows", () => {
    expect(getOrderedFlows([])).toEqual([]);
  });

  it("sorts ascending by order, stably preserving array position on ties", () => {
    const second = buildFlow({ id: "second", order: 2 });
    const first = buildFlow({ id: "first", order: 1 });
    const secondTie = buildFlow({ id: "second-tie", order: 2 });
    const flows = [second, first, secondTie];

    // order 1 first, then the two order-2 entries in original sequence
    expect(getOrderedFlows(flows).map((f) => f.id)).toEqual([
      "first",
      "second",
      "second-tie",
    ]);
  });
});

describe("getFlowById", () => {
  it("returns the matching flow when the id exists", () => {
    const addProvider = buildFlow({ id: "add-provider", order: 1 });
    const flows = [addProvider, buildFlow({ id: "other", order: 2 })];
    expect(getFlowById("add-provider", flows)).toBe(addProvider);
  });

  it("returns undefined when the id is unknown", () => {
    const flows = [buildFlow({ id: "add-provider", order: 1 })];
    expect(getFlowById("unknown-xyz", flows)).toBeUndefined();
  });
});

describe("getFirstIncompleteFlow", () => {
  const ctx: OnboardingContext = { hasProviders: false };

  it("returns undefined when the registry is empty", () => {
    expect(getFirstIncompleteFlow(ctx, fakeStore(), [])).toBeUndefined();
  });

  it("returns undefined when every flow is complete via isComplete(ctx)", () => {
    const flows = [
      buildFlow({ id: "a", order: 1, isComplete: () => true }),
      buildFlow({ id: "b", order: 2, isComplete: () => true }),
    ];
    expect(getFirstIncompleteFlow(ctx, fakeStore(), flows)).toBeUndefined();
  });

  it("returns the second flow when the first is complete via store record", () => {
    const first = buildFlow({ id: "first", order: 1, tour: buildTour("first") });
    const second = buildFlow({
      id: "second",
      order: 2,
      tour: buildTour("second"),
    });
    const store = fakeStore({ "first.v1": completedRecord("first") });

    // ordered evaluation skips the recorded flow
    expect(getFirstIncompleteFlow(ctx, store, [second, first])).toBe(second);
  });

  it("passes the provided context object through to isComplete", () => {
    let received: OnboardingContext | undefined;
    const flow = buildFlow({
      id: "captures",
      order: 1,
      isComplete: (c) => {
        received = c;
        return c.hasProviders;
      },
    });
    const providedCtx: OnboardingContext = { hasProviders: true };

    const result = getFirstIncompleteFlow(providedCtx, fakeStore(), [flow]);

    expect(received).toBe(providedCtx);
    expect(result).toBeUndefined();
  });

  it("treats isComplete(ctx) === true as complete even when a store record is absent", () => {
    const flow = buildFlow({
      id: "predicate-wins",
      order: 1,
      tour: buildTour("predicate-wins"),
      isComplete: () => true,
    });
    expect(getFirstIncompleteFlow(ctx, fakeStore(), [flow])).toBeUndefined();
  });

  it("returns the first incomplete flow when neither predicate nor record marks it complete", () => {
    const first = buildFlow({ id: "first", order: 1, tour: buildTour("first") });
    const second = buildFlow({
      id: "second",
      order: 2,
      tour: buildTour("second"),
      isComplete: () => true,
    });
    expect(getFirstIncompleteFlow(ctx, fakeStore(), [first, second])).toBe(
      first,
    );
  });
});
