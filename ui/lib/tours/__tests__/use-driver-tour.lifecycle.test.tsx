import { act, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { TourCompletionStore } from "../store/tour-completion-store";
import type { TourCompletionRecord, TourDefinition } from "../tour-types";
import { useDriverTour, type UseDriverTourResult } from "../use-driver-tour";

const driverHarness = vi.hoisted(() => {
  const instances: Array<{
    destroy: ReturnType<typeof vi.fn>;
    drive: ReturnType<typeof vi.fn>;
    isActive: ReturnType<typeof vi.fn>;
    isLastStep: ReturnType<typeof vi.fn>;
  }> = [];

  const driverMock = vi.fn((config: { onDestroyed?: () => void }) => {
    let active = false;
    const instance = {
      destroy: vi.fn(() => {
        active = false;
        config.onDestroyed?.();
      }),
      drive: vi.fn(() => {
        active = true;
      }),
      isActive: vi.fn(() => active),
      isLastStep: vi.fn(() => false),
      moveNext: vi.fn(),
      movePrevious: vi.fn(),
    };
    instances.push(instance);
    return instance;
  });

  return { driverMock, instances };
});

vi.mock("driver.js", () => ({
  driver: driverHarness.driverMock,
}));

const themeHarness = vi.hoisted(() => ({ resolvedTheme: "dark" }));

vi.mock("next-themes", () => ({
  useTheme: () => ({ resolvedTheme: themeHarness.resolvedTheme }),
}));

const tour = {
  id: "lifecycle-tour",
  version: 1,
  coversFiles: [],
  steps: [
    {
      title: "Welcome",
      description: "Tour lifecycle",
    },
  ],
} satisfies TourDefinition;

function createStore(): TourCompletionStore {
  const records = new Map<string, TourCompletionRecord>();

  return {
    get: ({ id, version }) => records.get(`${id}.${version}`) ?? null,
    set: ({ id, version }, record) => {
      records.set(`${id}.${version}`, record);
    },
    clear: ({ id, version }) => {
      records.delete(`${id}.${version}`);
    },
  };
}

function HookProbe({
  autoOpen,
  onResult,
  store,
}: {
  autoOpen: boolean;
  onResult: (result: UseDriverTourResult) => void;
  store: TourCompletionStore;
}) {
  const result = useDriverTour(tour, { autoOpen, store });
  onResult(result);
  return null;
}

describe("useDriverTour lifecycle", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "development");
    themeHarness.resolvedTheme = "dark";
    driverHarness.driverMock.mockClear();
    driverHarness.instances.length = 0;
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllEnvs();
  });

  it("does not destroy an active manually-started tour when autoOpen changes after replay param cleanup", () => {
    const store = createStore();
    let latestResult: UseDriverTourResult | undefined;

    const { rerender } = render(
      <HookProbe
        autoOpen={false}
        store={store}
        onResult={(result) => {
          latestResult = result;
        }}
      />,
    );

    expect(driverHarness.instances).toHaveLength(1);

    act(() => {
      latestResult?.start();
    });

    rerender(
      <HookProbe
        autoOpen
        store={store}
        onResult={(result) => {
          latestResult = result;
        }}
      />,
    );

    expect(driverHarness.instances[0].drive).toHaveBeenCalledTimes(1);
    expect(driverHarness.instances[0].destroy).not.toHaveBeenCalled();
  });

  it("still auto-opens a new incomplete tour after the configured delay", () => {
    vi.useFakeTimers();
    const store = createStore();

    render(
      <HookProbe
        autoOpen
        store={store}
        onResult={() => {
          // Result surface is irrelevant for auto-open behavior.
        }}
      />,
    );

    expect(driverHarness.instances).toHaveLength(1);
    expect(driverHarness.instances[0].drive).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(50);
    });

    expect(driverHarness.instances[0].drive).toHaveBeenCalledTimes(1);
  });

  it("does not record a completion when an active tour is torn down by a theme change", () => {
    const store = createStore();
    let latestResult: UseDriverTourResult | undefined;

    const { rerender } = render(
      <HookProbe
        autoOpen={false}
        store={store}
        onResult={(result) => {
          latestResult = result;
        }}
      />,
    );

    act(() => {
      latestResult?.start();
    });

    // Toggling theme re-runs the driver effect; its cleanup destroys the active
    // instance, which (like real driver.js) fires onDestroyed directly.
    act(() => {
      themeHarness.resolvedTheme = "light";
      rerender(
        <HookProbe
          autoOpen={false}
          store={store}
          onResult={(result) => {
            latestResult = result;
          }}
        />,
      );
    });

    // The first instance was destroyed and a fresh one created for the new theme...
    expect(driverHarness.instances[0].destroy).toHaveBeenCalledTimes(1);
    expect(driverHarness.instances).toHaveLength(2);
    // ...but no completion record was persisted, so the tour can reappear later.
    expect(store.get({ id: tour.id, version: tour.version })).toBeNull();
  });
});
