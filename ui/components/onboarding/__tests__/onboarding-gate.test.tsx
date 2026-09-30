import { act, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  FIRST_RUN_MAX_ATTEMPTS,
  isFirstRunHandled,
} from "@/lib/onboarding/first-run-marker";
import {
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_STEP,
  WIZARD_OPEN_SOURCE,
} from "@/lib/provider-funnel/provider-funnel-events";
import { addProviderTour } from "@/lib/tours/add-provider.tour";
import { localStorageAdapter } from "@/lib/tours/store/local-storage-adapter";

import { OnboardingGate } from "../onboarding-gate";

const replaceMock = vi.fn();
const armMock = vi.fn();
const pathnameMock = vi.fn();
const permissionsMock = vi.fn();

vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ permissions: permissionsMock() }),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: replaceMock }),
  usePathname: () => pathnameMock(),
}));

vi.mock("@/store/onboarding-checkpoint", () => ({
  useOnboardingCheckpointStore: {
    getState: () => ({ arm: armMock }),
  },
}));

const addProviderTourId = {
  id: addProviderTour.id,
  version: addProviderTour.version,
};

const TENANT_A = "11111111-1111-4111-8111-111111111111";
const TENANT_B = "22222222-2222-4222-8222-222222222222";

const CLOUD_FIRST_RUN_HREF =
  "/providers?addProvider=true&addProviderSource=first_run&onboarding=add-provider";
const OSS_FIRST_RUN_HREF =
  "/providers?addProvider=true&addProviderSource=first_run";

describe("OnboardingGate", () => {
  beforeEach(() => {
    window.localStorage.clear();
    replaceMock.mockClear();
    armMock.mockClear();
    pathnameMock.mockReturnValue("/");
    permissionsMock.mockReturnValue({ manage_providers: true });
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it.each(["/billing", "/billing/", "/billing/checkout"])(
    "defers the first run on %s without resolving it",
    (pathname) => {
      // Given
      pathnameMock.mockReturnValue(pathname);

      // When
      render(<OnboardingGate hasProviders={false} />);

      // Then
      expect(replaceMock).not.toHaveBeenCalled();
      expect(armMock).not.toHaveBeenCalled();
      expect(isFirstRunHandled()).toBe(false);
    },
  );

  it("sends the user to add a provider after leaving billing, without remounting the gate", async () => {
    // Given
    pathnameMock.mockReturnValue("/billing");
    const { rerender } = render(<OnboardingGate hasProviders={false} />);

    // When
    pathnameMock.mockReturnValue("/");
    rerender(<OnboardingGate hasProviders={false} />);

    // Then
    await waitFor(() =>
      expect(replaceMock).toHaveBeenCalledExactlyOnceWith(CLOUD_FIRST_RUN_HREF),
    );
  });

  it("does not defer on a route that only shares the billing prefix", async () => {
    // Given
    pathnameMock.mockReturnValue("/billing-history");

    // When
    render(<OnboardingGate hasProviders={false} />);

    // Then
    await waitFor(() => expect(replaceMock).toHaveBeenCalledOnce());
  });

  describe("when a Cloud tenant has no providers and never went through the first run", () => {
    it("opens the add-provider wizard with its tour and arms the checkpoint", async () => {
      // Given / When
      render(<OnboardingGate hasProviders={false} />);

      // Then
      await waitFor(() =>
        expect(replaceMock).toHaveBeenCalledExactlyOnceWith(
          CLOUD_FIRST_RUN_HREF,
        ),
      );
      expect(armMock).toHaveBeenCalledOnce();
    });

    it("tries again on the next load when the wizard never opened (the navigation was cut short)", async () => {
      // Given
      const { unmount } = render(
        <OnboardingGate hasProviders={false} tenantId={TENANT_A} />,
      );
      await waitFor(() => expect(replaceMock).toHaveBeenCalledOnce());
      unmount();
      replaceMock.mockClear();

      // When
      render(<OnboardingGate hasProviders={false} tenantId={TENANT_A} />);

      // Then
      await waitFor(() =>
        expect(replaceMock).toHaveBeenCalledExactlyOnceWith(
          CLOUD_FIRST_RUN_HREF,
        ),
      );
      expect(isFirstRunHandled(TENANT_A)).toBe(false);
    });

    it("is resolved once the add-provider wizard opens, so later loads leave the user alone", async () => {
      // Given
      const { unmount } = render(
        <OnboardingGate hasProviders={false} tenantId={TENANT_A} />,
      );
      await waitFor(() => expect(replaceMock).toHaveBeenCalledOnce());
      act(() => {
        dispatchProviderFunnel({
          step: PROVIDER_FUNNEL_STEP.WIZARD_OPENED,
          source: WIZARD_OPEN_SOURCE.FIRST_RUN,
        });
      });
      unmount();
      replaceMock.mockClear();

      // When
      render(<OnboardingGate hasProviders={false} tenantId={TENANT_A} />);

      // Then
      expect(isFirstRunHandled(TENANT_A)).toBe(true);
      expect(replaceMock).not.toHaveBeenCalled();
    });

    it("gives up after a few attempts that never reached the wizard, so no browser is trapped", async () => {
      // Given: three loads whose navigation never completed.
      for (let attempt = 0; attempt < FIRST_RUN_MAX_ATTEMPTS; attempt++) {
        const { unmount } = render(
          <OnboardingGate hasProviders={false} tenantId={TENANT_A} />,
        );
        await waitFor(() => expect(replaceMock).toHaveBeenCalledOnce());
        unmount();
        replaceMock.mockClear();
      }

      // When
      render(<OnboardingGate hasProviders={false} tenantId={TENANT_A} />);

      // Then
      expect(isFirstRunHandled(TENANT_A)).toBe(true);
      expect(replaceMock).not.toHaveBeenCalled();
    });

    it.each(["true", "1legacy", "-1"])(
      "honours a browser-wide marker holding %s, written before markers counted attempts",
      (value) => {
        // Given: e2e storage state and pre-existing browsers set the bare key.
        window.localStorage.setItem("prowler.onboarding.first-run", value);

        // When
        render(<OnboardingGate hasProviders={false} tenantId={TENANT_A} />);

        // Then
        expect(replaceMock).not.toHaveBeenCalled();
        expect(isFirstRunHandled(TENANT_A)).toBe(true);
      },
    );

    it("still runs for a different empty tenant on the same browser", async () => {
      // Given: tenant A went through its first run on this browser.
      const { unmount } = render(
        <OnboardingGate hasProviders={false} tenantId={TENANT_A} />,
      );
      await waitFor(() => expect(replaceMock).toHaveBeenCalledOnce());
      act(() => {
        dispatchProviderFunnel({
          step: PROVIDER_FUNNEL_STEP.WIZARD_OPENED,
          source: WIZARD_OPEN_SOURCE.FIRST_RUN,
        });
      });
      unmount();
      replaceMock.mockClear();

      // When
      render(<OnboardingGate hasProviders={false} tenantId={TENANT_B} />);

      // Then
      await waitFor(() => expect(replaceMock).toHaveBeenCalledOnce());
      expect(isFirstRunHandled(TENANT_A)).toBe(true);
      expect(isFirstRunHandled(TENANT_B)).toBe(false);
    });
  });

  describe("when a self-hosted deployment has no providers", () => {
    it("opens the add-provider wizard without the Cloud-only tour or checkpoint", async () => {
      // Given
      vi.stubEnv("UI_CLOUD_ENABLED", "false");

      // When
      render(<OnboardingGate hasProviders={false} />);

      // Then
      await waitFor(() =>
        expect(replaceMock).toHaveBeenCalledExactlyOnceWith(OSS_FIRST_RUN_HREF),
      );
      expect(armMock).not.toHaveBeenCalled();
    });

    it("tries again on the next load when the wizard never opened, with no tenant id available", async () => {
      // Given: self-hosted layouts mount the gate without a tenant id.
      vi.stubEnv("UI_CLOUD_ENABLED", "false");
      const { unmount } = render(<OnboardingGate hasProviders={false} />);
      await waitFor(() => expect(replaceMock).toHaveBeenCalledOnce());
      unmount();
      replaceMock.mockClear();

      // When
      render(<OnboardingGate hasProviders={false} />);

      // Then
      await waitFor(() =>
        expect(replaceMock).toHaveBeenCalledExactlyOnceWith(OSS_FIRST_RUN_HREF),
      );
      expect(isFirstRunHandled()).toBe(false);
    });
  });

  describe("when the user cannot add providers", () => {
    it("leaves the user where they are, since an empty list may just be limited visibility", () => {
      // Given
      permissionsMock.mockReturnValue({ manage_providers: false });

      // When
      render(<OnboardingGate hasProviders={false} />);

      // Then
      expect(replaceMock).not.toHaveBeenCalled();
      expect(isFirstRunHandled()).toBe(false);
    });
  });

  describe("when the tenant already has providers", () => {
    it("leaves the user where they are", () => {
      // Given / When
      render(<OnboardingGate hasProviders />);

      // Then
      expect(replaceMock).not.toHaveBeenCalled();
      expect(isFirstRunHandled()).toBe(false);
    });
  });

  describe("when the add-provider tour was already resolved in this browser", () => {
    it("leaves the user where they are", () => {
      // Given
      localStorageAdapter.set(addProviderTourId, {
        tourId: addProviderTour.id,
        version: addProviderTour.version,
        state: "dismissed",
        completedAt: new Date().toISOString(),
      });

      // When
      render(<OnboardingGate hasProviders={false} />);

      // Then
      expect(replaceMock).not.toHaveBeenCalled();
      expect(armMock).not.toHaveBeenCalled();
    });
  });

  describe("when the provider count is unknown (fail-open)", () => {
    it("leaves the user where they are when the fetch failed", () => {
      // Given / When
      render(<OnboardingGate hasProviders={undefined} />);

      // Then
      expect(replaceMock).not.toHaveBeenCalled();
    });

    it("can be mounted with the prop omitted entirely", () => {
      // Given / When
      render(<OnboardingGate />);

      // Then
      expect(replaceMock).not.toHaveBeenCalled();
    });
  });
});
