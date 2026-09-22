import { render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { isFirstRunHandled } from "@/lib/onboarding/first-run-marker";
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

    it("happens only once per tenant on this browser", async () => {
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
      expect(isFirstRunHandled(TENANT_A)).toBe(true);
      expect(replaceMock).not.toHaveBeenCalled();
    });

    it("still runs for a different empty tenant on the same browser", async () => {
      // Given
      const { unmount } = render(
        <OnboardingGate hasProviders={false} tenantId={TENANT_A} />,
      );
      await waitFor(() => expect(replaceMock).toHaveBeenCalledOnce());
      unmount();
      replaceMock.mockClear();

      // When
      render(<OnboardingGate hasProviders={false} tenantId={TENANT_B} />);

      // Then
      await waitFor(() => expect(replaceMock).toHaveBeenCalledOnce());
      expect(isFirstRunHandled(TENANT_B)).toBe(true);
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
