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

// Minimal valid TourDefinition stub used to build OnboardingFlow fixtures.
// The registry never reads tour internals beyond { id, version } (TourId), so
// a flat definition is sufficient for these pure-logic tests.
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

// In-memory store implementing the TourCompletionStore contract. Injecting it
// keeps getFirstIncompleteFlow unit-testable with no localStorage mocking.
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
    // Given - a flow object that exercises every field of the contract
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

    // When / Then - the contract resolves at runtime
    expect(flow.id).toBe("add-provider");
    expect(flow.order).toBe(1);
    expect(flow.route).toBe("/providers");
    expect(flow.isComplete?.(ctx)).toBe(false);
    expect(flow.isComplete?.({ hasProviders: true })).toBe(true);
  });
});

describe("onboardingFlows (production registry)", () => {
  it("registers the add-provider flow as the first onboarding flow", () => {
    // Given / When - the production registry after Slice B registration
    const addProvider = getFlowById("add-provider", onboardingFlows);

    // Then - the entry exists with its declared contract
    expect(addProvider).toBeDefined();
    expect(addProvider?.order).toBe(1);
    expect(addProvider?.route).toBe("/providers");
    expect(addProvider?.tour.id).toBe("add-provider");
  });

  it("treats add-provider as complete when the context reports providers", () => {
    // Given - the production add-provider flow's completion predicate
    const addProvider = getFlowById("add-provider", onboardingFlows);

    // Then - isComplete delegates to the server-derived hasProviders signal
    expect(addProvider?.isComplete?.({ hasProviders: true })).toBe(true);
    expect(addProvider?.isComplete?.({ hasProviders: false })).toBe(false);
  });

  it("registers the view-first-scan flow at order 2 on the scans route", () => {
    // Given / When - the sequence flow added in Slice 4
    const flow = getFlowById("view-first-scan", onboardingFlows);

    // Then - declared contract: order, route, and a matching tour id
    expect(flow).toBeDefined();
    expect(flow?.order).toBe(2);
    expect(flow?.route).toBe("/scans");
    expect(flow?.tour.id).toBe("view-first-scan");
  });

  it("registers the explore-findings flow at order 3 on the findings route", () => {
    // Given / When - the sequence flow added in Slice 5
    const flow = getFlowById("explore-findings", onboardingFlows);

    // Then - declared contract: order, route, and a matching tour id
    expect(flow).toBeDefined();
    expect(flow?.order).toBe(3);
    expect(flow?.route).toBe("/findings");
    expect(flow?.tour.id).toBe("explore-findings");
  });

  it("registers the view-compliance flow at order 4 on the compliance route", () => {
    // Given / When - the sequence flow added in Slice 6
    const flow = getFlowById("view-compliance", onboardingFlows);

    // Then - declared contract: order, route, and a matching tour id
    expect(flow).toBeDefined();
    expect(flow?.order).toBe(4);
    expect(flow?.route).toBe("/compliance");
    expect(flow?.tour.id).toBe("view-compliance");
  });

  it("registers the attack-paths flow at order 5 on the attack-paths route", () => {
    // Given / When - the integration flow added in Slice 7
    const flow = getFlowById("attack-paths", onboardingFlows);

    // Then - declared contract: order, route, and a matching tour id
    expect(flow).toBeDefined();
    expect(flow?.order).toBe(5);
    expect(flow?.route).toBe("/attack-paths");
    expect(flow?.tour.id).toBe("attack-paths");
  });

  it("flags attack-paths with ownsAutoOpen so the shared trigger never drives it", () => {
    // Given / When - the attack-paths page owns its own driver (Decision 4)
    const attackPaths = getFlowById("attack-paths", onboardingFlows);

    // Then - only attack-paths carries the flag; every other flow is falsy
    expect(attackPaths?.ownsAutoOpen).toBe(true);
    for (const flow of onboardingFlows) {
      if (flow.id === "attack-paths") continue;
      expect(flow.ownsAutoOpen).toBeFalsy();
    }
  });

  it("orders the five sequence flows 1..5 by registry order", () => {
    // Given / When - the production registry after Slices 4-7 registration
    const ordered = getOrderedFlows(onboardingFlows);

    // Then - the guided sequence advances in declared order
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
    // Given / When / Then - the index forwards the same callable references
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
    // Given - the empty production registry
    // When
    const result = getOrderedFlows([]);

    // Then
    expect(result).toEqual([]);
  });

  it("sorts ascending by order, stably preserving array position on ties", () => {
    // Given - entries declared out of order, plus a tie on order 2
    const second = buildFlow({ id: "second", order: 2 });
    const first = buildFlow({ id: "first", order: 1 });
    const secondTie = buildFlow({ id: "second-tie", order: 2 });
    const flows = [second, first, secondTie];

    // When
    const result = getOrderedFlows(flows);

    // Then - order 1 first, then the two order-2 entries in original sequence
    expect(result.map((f) => f.id)).toEqual(["first", "second", "second-tie"]);
  });
});

describe("getFlowById", () => {
  it("returns the matching flow when the id exists", () => {
    // Given
    const addProvider = buildFlow({ id: "add-provider", order: 1 });
    const flows = [addProvider, buildFlow({ id: "other", order: 2 })];

    // When
    const result = getFlowById("add-provider", flows);

    // Then
    expect(result).toBe(addProvider);
  });

  it("returns undefined when the id is unknown", () => {
    // Given
    const flows = [buildFlow({ id: "add-provider", order: 1 })];

    // When
    const result = getFlowById("unknown-xyz", flows);

    // Then
    expect(result).toBeUndefined();
  });
});

describe("getFirstIncompleteFlow", () => {
  const ctx: OnboardingContext = { hasProviders: false };

  it("returns undefined when the registry is empty", () => {
    // Given - no flows
    // When
    const result = getFirstIncompleteFlow(ctx, fakeStore(), []);

    // Then
    expect(result).toBeUndefined();
  });

  it("returns undefined when every flow is complete via isComplete(ctx)", () => {
    // Given - both flows report complete through their predicate
    const flows = [
      buildFlow({ id: "a", order: 1, isComplete: () => true }),
      buildFlow({ id: "b", order: 2, isComplete: () => true }),
    ];

    // When
    const result = getFirstIncompleteFlow(ctx, fakeStore(), flows);

    // Then
    expect(result).toBeUndefined();
  });

  it("returns the second flow when the first is complete via store record", () => {
    // Given - first flow has a persisted completion record, second does not
    const first = buildFlow({
      id: "first",
      order: 1,
      tour: buildTour("first"),
    });
    const second = buildFlow({
      id: "second",
      order: 2,
      tour: buildTour("second"),
    });
    const store = fakeStore({ "first.v1": completedRecord("first") });

    // When
    const result = getFirstIncompleteFlow(ctx, store, [second, first]);

    // Then - ordered evaluation skips the recorded flow, returns the next
    expect(result).toBe(second);
  });

  it("passes the provided context object through to isComplete", () => {
    // Given - a predicate that captures the context it receives
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

    // When
    const result = getFirstIncompleteFlow(providedCtx, fakeStore(), [flow]);

    // Then - the exact context object was forwarded, flow counted complete
    expect(received).toBe(providedCtx);
    expect(result).toBeUndefined();
  });

  it("treats isComplete(ctx) === true as complete even when a store record is absent", () => {
    // Given - no store record at all, but predicate says complete
    const flow = buildFlow({
      id: "predicate-wins",
      order: 1,
      tour: buildTour("predicate-wins"),
      isComplete: () => true,
    });

    // When
    const result = getFirstIncompleteFlow(ctx, fakeStore(), [flow]);

    // Then
    expect(result).toBeUndefined();
  });

  it("returns the first incomplete flow when neither predicate nor record marks it complete", () => {
    // Given - first flow incomplete (no record, no predicate), second complete
    const first = buildFlow({
      id: "first",
      order: 1,
      tour: buildTour("first"),
    });
    const second = buildFlow({
      id: "second",
      order: 2,
      tour: buildTour("second"),
      isComplete: () => true,
    });

    // When
    const result = getFirstIncompleteFlow(ctx, fakeStore(), [first, second]);

    // Then
    expect(result).toBe(first);
  });
});
