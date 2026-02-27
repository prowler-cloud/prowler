import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useOrgSetupStore } from "@/store/organizations/store";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { ORG_WIZARD_STEP } from "@/types/organizations";
import {
  PROVIDER_WIZARD_MODE,
  PROVIDER_WIZARD_STEP,
} from "@/types/provider-wizard";

import { useProviderWizardController } from "./use-provider-wizard-controller";

vi.mock("next-auth/react", () => ({
  useSession: () => ({
    data: null,
    status: "unauthenticated",
  }),
}));

describe("useProviderWizardController", () => {
  beforeEach(() => {
    vi.useRealTimers();
    sessionStorage.clear();
    localStorage.clear();
    useProviderWizardStore.getState().reset();
    useOrgSetupStore.getState().reset();
  });

  it("hydrates update mode when initial data is provided", async () => {
    // Given
    const onOpenChange = vi.fn();

    // When
    const { result } = renderHook(() =>
      useProviderWizardController({
        open: true,
        onOpenChange,
        initialData: {
          providerId: "provider-1",
          providerType: "aws",
          providerUid: "111111111111",
          providerAlias: "production",
          secretId: "secret-1",
          mode: PROVIDER_WIZARD_MODE.UPDATE,
        },
      }),
    );

    // Then
    await waitFor(() => {
      expect(result.current.currentStep).toBe(PROVIDER_WIZARD_STEP.CREDENTIALS);
    });
    expect(result.current.modalTitle).toBe("Update Provider Credentials");
    expect(result.current.isProviderFlow).toBe(true);
    expect(result.current.docsLink).toBe(
      "https://goto.prowler.com/provider-aws",
    );

    const state = useProviderWizardStore.getState();
    expect(state.providerId).toBe("provider-1");
    expect(state.providerType).toBe("aws");
    expect(state.providerUid).toBe("111111111111");
    expect(state.providerAlias).toBe("production");
    expect(state.secretId).toBe("secret-1");
    expect(state.mode).toBe(PROVIDER_WIZARD_MODE.UPDATE);
  });

  it("switches into and out of organizations flow", () => {
    // Given
    const onOpenChange = vi.fn();
    const { result } = renderHook(() =>
      useProviderWizardController({
        open: true,
        onOpenChange,
      }),
    );

    // When
    act(() => {
      result.current.openOrganizationsFlow();
    });

    // Then
    expect(result.current.wizardVariant).toBe("organizations");
    expect(result.current.isProviderFlow).toBe(false);
    expect(result.current.orgCurrentStep).toBe(ORG_WIZARD_STEP.SETUP);
    expect(result.current.docsLink).toBe(
      "https://docs.prowler.com/user-guide/tutorials/prowler-cloud-aws-organizations",
    );

    // When
    act(() => {
      result.current.backToProviderFlow();
    });

    // Then
    expect(result.current.wizardVariant).toBe("provider");
    expect(result.current.isProviderFlow).toBe(true);
    expect(result.current.currentStep).toBe(PROVIDER_WIZARD_STEP.CONNECT);
  });

  it("moves to launch step after a successful connection test in add mode", () => {
    // Given
    const onOpenChange = vi.fn();
    const { result } = renderHook(() =>
      useProviderWizardController({
        open: true,
        onOpenChange,
      }),
    );

    // When
    act(() => {
      result.current.setCurrentStep(PROVIDER_WIZARD_STEP.TEST);
      result.current.handleTestSuccess();
    });

    // Then
    expect(result.current.currentStep).toBe(PROVIDER_WIZARD_STEP.LAUNCH);
    expect(onOpenChange).not.toHaveBeenCalled();
  });

  it("does not override launch footer config in the controller", () => {
    // Given
    const onOpenChange = vi.fn();
    const { result } = renderHook(() =>
      useProviderWizardController({
        open: true,
        onOpenChange,
      }),
    );

    // When
    act(() => {
      result.current.setCurrentStep(PROVIDER_WIZARD_STEP.LAUNCH);
    });

    // Then
    expect(result.current.resolvedFooterConfig.showAction).toBe(false);
    expect(result.current.resolvedFooterConfig.showBack).toBe(false);
    expect(onOpenChange).not.toHaveBeenCalled();
  });

  it("does not reset organizations step when org store updates while modal is open", () => {
    // Given
    const onOpenChange = vi.fn();
    const { result } = renderHook(() =>
      useProviderWizardController({
        open: true,
        onOpenChange,
      }),
    );

    act(() => {
      result.current.openOrganizationsFlow();
      result.current.setOrgCurrentStep(ORG_WIZARD_STEP.VALIDATE);
    });

    // When
    act(() => {
      useOrgSetupStore
        .getState()
        .setOrganization("org-1", "My Org", "o-abc123def4");
      useOrgSetupStore.getState().setDiscovery("disc-1", {
        roots: [],
        organizational_units: [],
        accounts: [],
      });
    });

    // Then
    expect(result.current.wizardVariant).toBe("organizations");
    expect(result.current.orgCurrentStep).toBe(ORG_WIZARD_STEP.VALIDATE);
  });

  it("does not rehydrate wizard state when initial data changes while modal remains open", async () => {
    // Given
    const onOpenChange = vi.fn();
    const { result, rerender } = renderHook(
      ({
        open,
        initialData,
      }: {
        open: boolean;
        initialData?: {
          providerId: string;
          providerType: "gcp";
          providerUid: string;
          providerAlias: string;
          secretId: string | null;
          mode: "add" | "update";
        };
      }) =>
        useProviderWizardController({
          open,
          onOpenChange,
          initialData,
        }),
      {
        initialProps: {
          open: true,
          initialData: {
            providerId: "provider-1",
            providerType: "gcp",
            providerUid: "project-123",
            providerAlias: "gcp-main",
            secretId: null,
            mode: PROVIDER_WIZARD_MODE.ADD,
          },
        },
      },
    );

    await waitFor(() => {
      expect(result.current.currentStep).toBe(PROVIDER_WIZARD_STEP.CREDENTIALS);
    });

    act(() => {
      useProviderWizardStore.getState().setVia("service-account");
      result.current.setCurrentStep(PROVIDER_WIZARD_STEP.TEST);
    });

    // When: provider data refreshes while modal is still open
    rerender({
      open: true,
      initialData: {
        providerId: "provider-1",
        providerType: "gcp",
        providerUid: "project-123",
        providerAlias: "gcp-main",
        secretId: "secret-1",
        mode: PROVIDER_WIZARD_MODE.UPDATE,
      },
    });

    // Then: keep user progress in the current flow
    expect(result.current.currentStep).toBe(PROVIDER_WIZARD_STEP.TEST);
    expect(useProviderWizardStore.getState().via).toBe("service-account");
  });
});
