import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ONBOARDING_INVITE_STEP_EVENT,
  type OnboardingInviteStepDetail,
} from "@/lib/onboarding/onboarding-events";

import { OnboardingInviteStep } from "../onboarding-invite-step";

const { getRolesMock, sendInviteMock, toastMock } = vi.hoisted(() => ({
  getRolesMock: vi.fn(),
  sendInviteMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/actions/onboarding/invite", () => ({
  getOnboardingInviteRoles: getRolesMock,
}));

vi.mock("@/actions/invitations/invitation", () => ({
  sendInvite: sendInviteMock,
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/shadcn")>()),
  useToast: () => ({ toast: toastMock }),
}));

// Radix Select does not open in jsdom; a native select keeps the test on the
// form's behaviour rather than the dropdown's.
vi.mock("@/components/shadcn/select/select", () => ({
  Select: ({
    value,
    onValueChange,
    disabled,
    children,
  }: {
    value?: string;
    onValueChange: (value: string) => void;
    disabled?: boolean;
    children: React.ReactNode;
  }) => (
    <select
      aria-label="Select a role"
      value={value ?? ""}
      disabled={disabled}
      onChange={(event) => onValueChange(event.target.value)}
    >
      <option value="">Select a role</option>
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: React.ReactNode }) => (
    <>{children}</>
  ),
  SelectItem: ({
    value,
    children,
  }: {
    value: string;
    children: React.ReactNode;
  }) => <option value={value}>{children}</option>,
}));

const ROLES = [
  { id: "11111111-1111-4111-8111-111111111111", name: "member" },
  { id: "22222222-2222-4222-8222-222222222222", name: "admin" },
];

describe("OnboardingInviteStep", () => {
  const outcomes: OnboardingInviteStepDetail[] = [];
  const recordOutcome = (event: Event) => {
    outcomes.push((event as CustomEvent<OnboardingInviteStepDetail>).detail);
  };

  beforeEach(() => {
    outcomes.length = 0;
    window.addEventListener(ONBOARDING_INVITE_STEP_EVENT, recordOutcome);
    getRolesMock.mockReset().mockResolvedValue(ROLES);
    sendInviteMock.mockReset().mockResolvedValue({ data: { id: "inv-1" } });
    toastMock.mockReset();
  });

  afterEach(() => {
    window.removeEventListener(ONBOARDING_INVITE_STEP_EVENT, recordOutcome);
  });

  it("announces the impression and renders the invitation form once roles load", async () => {
    // When
    render(<OnboardingInviteStep onDone={vi.fn()} />);

    // Then
    expect(outcomes).toEqual([{ outcome: "shown" }]);
    expect(await screen.findByText("Invite your team")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /send invitation/i }),
    ).toBeInTheDocument();
    // The admin role is listed first so it is the natural pick.
    const options = screen.getAllByRole("option").map((o) => o.textContent);
    expect(options).toEqual(["Select a role", "admin", "member"]);
  });

  it("sends the invitation tagged for onboarding and resolves the step", async () => {
    // Given
    const user = userEvent.setup();
    const onDone = vi.fn();
    render(<OnboardingInviteStep onDone={onDone} />);
    await screen.findByText("Invite your team");

    // When
    await user.type(screen.getByLabelText(/email/i), "teammate@company.com");
    await user.selectOptions(screen.getByRole("combobox"), ROLES[1].id);
    await user.click(screen.getByRole("button", { name: /send invitation/i }));

    // Then
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    const formData = sendInviteMock.mock.calls[0]?.[0] as FormData;
    expect(formData.get("email")).toBe("teammate@company.com");
    expect(formData.get("role")).toBe(ROLES[1].id);
    expect(formData.get("source")).toBe("onboarding");
    expect(outcomes).toEqual([{ outcome: "shown" }, { outcome: "submitted" }]);
  });

  it("keeps the step open when the API rejects the invitation", async () => {
    // Given
    const user = userEvent.setup();
    const onDone = vi.fn();
    sendInviteMock.mockResolvedValue({
      errors: [
        {
          detail: "This email has already been invited.",
          source: { pointer: "/data/attributes/email" },
        },
      ],
    });
    render(<OnboardingInviteStep onDone={onDone} />);
    await screen.findByText("Invite your team");

    // When
    await user.type(screen.getByLabelText(/email/i), "teammate@company.com");
    await user.selectOptions(screen.getByRole("combobox"), ROLES[1].id);
    await user.click(screen.getByRole("button", { name: /send invitation/i }));

    // Then
    expect(
      await screen.findByText("This email has already been invited."),
    ).toBeInTheDocument();
    expect(onDone).not.toHaveBeenCalled();
    expect(outcomes).toEqual([{ outcome: "shown" }]);
  });

  it("records a skip and resolves the step", async () => {
    // Given
    const user = userEvent.setup();
    const onDone = vi.fn();
    render(<OnboardingInviteStep onDone={onDone} />);
    await screen.findByText("Invite your team");

    // When
    await user.click(screen.getByRole("button", { name: "Skip for now" }));

    // Then
    expect(outcomes.at(-1)).toEqual({ outcome: "skipped" });
    expect(onDone).toHaveBeenCalledTimes(1);
    expect(sendInviteMock).not.toHaveBeenCalled();
  });

  it("still lets the user skip when roles cannot be loaded", async () => {
    // Given
    const user = userEvent.setup();
    const onDone = vi.fn();
    getRolesMock.mockRejectedValue(new Error("roles unavailable"));
    render(<OnboardingInviteStep onDone={onDone} />);
    await screen.findByText("Invite your team");

    // Then
    expect(screen.getByText(/Roles could not be loaded/)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /send invitation/i }),
    ).not.toBeInTheDocument();

    // When
    await user.click(screen.getByRole("button", { name: "Skip for now" }));

    // Then
    expect(onDone).toHaveBeenCalledTimes(1);
  });
});
