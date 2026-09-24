import { afterEach, describe, expect, it, vi } from "vitest";

import {
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_EVENT,
  PROVIDER_FUNNEL_STEP,
  type ProviderFunnelDetail,
  WIZARD_OPEN_SOURCE,
} from "./provider-funnel-events";

describe("dispatchProviderFunnel", () => {
  const listeners: EventListener[] = [];

  const listen = (listener: (detail: ProviderFunnelDetail) => void) => {
    const handler: EventListener = (event) =>
      listener((event as CustomEvent<ProviderFunnelDetail>).detail);
    listeners.push(handler);
    window.addEventListener(PROVIDER_FUNNEL_EVENT, handler);
  };

  afterEach(() => {
    listeners
      .splice(0)
      .forEach((handler) =>
        window.removeEventListener(PROVIDER_FUNNEL_EVENT, handler),
      );
  });

  it("delivers the step detail to an outside window listener", () => {
    const received = vi.fn();
    listen(received);

    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.WIZARD_OPENED,
      source: WIZARD_OPEN_SOURCE.SIDEBAR_CTA,
    });

    expect(received).toHaveBeenCalledExactlyOnceWith({
      step: "wizard_opened",
      source: "sidebar_cta",
    });
  });

  it("is a no-op during server rendering, where there is no window", () => {
    vi.stubGlobal("window", undefined);

    expect(() =>
      dispatchProviderFunnel({
        step: PROVIDER_FUNNEL_STEP.PROVIDER_TYPE_SELECTED,
        providerType: "aws",
      }),
    ).not.toThrow();

    vi.unstubAllGlobals();
  });
});
