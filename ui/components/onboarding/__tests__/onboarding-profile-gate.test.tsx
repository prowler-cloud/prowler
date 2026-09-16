import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ONBOARDING_PROFILE_STEP_EVENT,
  type OnboardingProfileStepDetail,
} from "@/lib/onboarding/onboarding-events";
import { onboardingProfileMarkerKey } from "@/lib/onboarding/profile-marker";

import { OnboardingProfileGate } from "../onboarding-profile-gate";

const { pathnameMock, submitMock, skipMock } = vi.hoisted(() => ({
  pathnameMock: vi.fn(),
  submitMock: vi.fn(),
  skipMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => pathnameMock(),
}));

vi.mock("@/actions/onboarding/profile", () => ({
  submitOnboardingProfile: submitMock,
  skipOnboardingProfile: skipMock,
}));

vi.mock("../onboarding-gate", () => ({
  OnboardingGate: ({ hasProviders }: { hasProviders?: boolean }) => (
    <div data-testid="tour-gate" data-has-providers={String(hasProviders)} />
  ),
}));

const TENANT_ID = "3f6c2f1e-7b0a-4d5c-9a21-0c9f4f2a7b10";
const OTHER_TENANT_ID = "8a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const MARKER_KEY = onboardingProfileMarkerKey(TENANT_ID) as string;

const ANSWERS = {
  declared_cloud_accounts: "11-50",
  declared_team_size: "2-5",
  declared_role: "security",
  declared_seniority: "director",
} as const;

const answerEverything = async (user: ReturnType<typeof userEvent.setup>) => {
  await user.click(screen.getByRole("radio", { name: "11-50" }));
  await user.click(screen.getByRole("radio", { name: "2-5" }));
  await user.click(screen.getByRole("radio", { name: "Security" }));
  await user.click(screen.getByRole("radio", { name: "Director / Head of" }));
  await user.click(screen.getByRole("button", { name: "Continue" }));
};

describe("OnboardingProfileGate", () => {
  const outcomes: OnboardingProfileStepDetail[] = [];
  const recordOutcome = (event: Event) => {
    outcomes.push((event as CustomEvent<OnboardingProfileStepDetail>).detail);
  };

  beforeEach(() => {
    window.localStorage.clear();
    outcomes.length = 0;
    window.addEventListener(ONBOARDING_PROFILE_STEP_EVENT, recordOutcome);
    pathnameMock.mockReturnValue("/");
    submitMock.mockReset().mockResolvedValue({ stored: true });
    skipMock.mockReset().mockResolvedValue({ stored: true });
  });

  afterEach(() => {
    window.removeEventListener(ONBOARDING_PROFILE_STEP_EVENT, recordOutcome);
  });

  it("asks the profile before the tour gate for a provably new tenant", async () => {
    // When
    render(
      <OnboardingProfileGate
        hasProviders={false}
        profileRecorded={false}
        tenantId={TENANT_ID}
      />,
    );

    // Then
    expect(
      await screen.findByRole("button", { name: "Continue" }),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("tour-gate")).not.toBeInTheDocument();
    expect(outcomes).toEqual([{ outcome: "shown" }]);
  });

  it("stores the answers, announces them and hands over to the tour gate", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <OnboardingProfileGate
        hasProviders={false}
        profileRecorded={false}
        tenantId={TENANT_ID}
      />,
    );
    await screen.findByRole("button", { name: "Continue" });

    // When
    await answerEverything(user);

    // Then
    await waitFor(() =>
      expect(screen.getByTestId("tour-gate")).toBeInTheDocument(),
    );
    expect(submitMock).toHaveBeenCalledWith(ANSWERS);
    expect(outcomes).toEqual([
      { outcome: "shown" },
      { outcome: "submitted", answers: ANSWERS },
    ]);
    expect(window.localStorage.getItem(MARKER_KEY)).toBe("true");
    expect(screen.getByTestId("tour-gate")).toHaveAttribute(
      "data-has-providers",
      "false",
    );
  });

  it("records a skip as an announced outcome and as a stored fact", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <OnboardingProfileGate
        hasProviders={false}
        profileRecorded={false}
        tenantId={TENANT_ID}
      />,
    );
    await screen.findByRole("button", { name: "Skip" });

    // When
    await user.click(screen.getByRole("button", { name: "Skip" }));

    // Then
    expect(outcomes.at(-1)).toEqual({ outcome: "skipped" });
    expect(skipMock).toHaveBeenCalledTimes(1);
    expect(window.localStorage.getItem(MARKER_KEY)).toBe("true");
    expect(screen.getByTestId("tour-gate")).toBeInTheDocument();
  });

  it("leaves no marker when the API rejects the answers, so the step returns next login", async () => {
    // Given
    const user = userEvent.setup();
    submitMock.mockResolvedValue({ stored: false, error: "boom" });
    render(
      <OnboardingProfileGate
        hasProviders={false}
        profileRecorded={false}
        tenantId={TENANT_ID}
      />,
    );
    await screen.findByRole("button", { name: "Continue" });

    // When
    await answerEverything(user);

    // Then — closed for this session, but nothing durable was written.
    await waitFor(() =>
      expect(screen.getByTestId("tour-gate")).toBeInTheDocument(),
    );
    expect(window.localStorage.getItem(MARKER_KEY)).toBeNull();
    expect(outcomes).toEqual([{ outcome: "shown" }]);
  });

  it.each([
    [
      "the profile is already recorded",
      { hasProviders: false, profileRecorded: true },
    ],
    [
      "the profile read failed",
      { hasProviders: false, profileRecorded: undefined },
    ],
    ["providers exist", { hasProviders: true, profileRecorded: false }],
  ])("goes straight to the tour gate when %s", async (_, props) => {
    // When
    render(<OnboardingProfileGate {...props} tenantId={TENANT_ID} />);

    // Then
    expect(screen.getByTestId("tour-gate")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Continue" })).toBeNull(),
    );
    expect(outcomes).toEqual([]);
  });

  it("does not reopen once this browser handled the step", () => {
    // Given
    window.localStorage.setItem(MARKER_KEY, "true");

    // When
    render(
      <OnboardingProfileGate
        hasProviders={false}
        profileRecorded={false}
        tenantId={TENANT_ID}
      />,
    );

    // Then
    expect(screen.getByTestId("tour-gate")).toBeInTheDocument();
    expect(outcomes).toEqual([]);
  });

  it("defers on billing routes without resolving the step", () => {
    // Given
    pathnameMock.mockReturnValue("/billing");

    // When
    render(
      <OnboardingProfileGate
        hasProviders={false}
        profileRecorded={false}
        tenantId={TENANT_ID}
      />,
    );

    // Then
    expect(screen.getByTestId("tour-gate")).toBeInTheDocument();
    expect(window.localStorage.getItem(MARKER_KEY)).toBeNull();
    expect(outcomes).toEqual([]);
  });

  it("still asks another tenant that the same browser has not answered", async () => {
    // Given — this browser answered for one tenant.
    window.localStorage.setItem(MARKER_KEY, "true");

    // When — the user switches to a second, brand-new tenant.
    render(
      <OnboardingProfileGate
        hasProviders={false}
        profileRecorded={false}
        tenantId={OTHER_TENANT_ID}
      />,
    );

    // Then
    expect(
      await screen.findByRole("button", { name: "Continue" }),
    ).toBeInTheDocument();
    expect(outcomes).toEqual([{ outcome: "shown" }]);
  });

  it("leaves no marker and announces nothing when the skip is not stored", async () => {
    // Given
    const user = userEvent.setup();
    skipMock.mockResolvedValue({ stored: false, error: "boom" });
    render(
      <OnboardingProfileGate
        hasProviders={false}
        profileRecorded={false}
        tenantId={TENANT_ID}
      />,
    );
    await screen.findByRole("button", { name: "Skip" });

    // When
    await user.click(screen.getByRole("button", { name: "Skip" }));

    // Then
    await waitFor(() =>
      expect(screen.getByTestId("tour-gate")).toBeInTheDocument(),
    );
    expect(window.localStorage.getItem(MARKER_KEY)).toBeNull();
    expect(outcomes).toEqual([{ outcome: "shown" }]);
  });
});
