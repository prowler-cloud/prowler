import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SendInvitationForm } from "./send-invitation-form";

const { pushMock, sendInviteMock } = vi.hoisted(() => ({
  pushMock: vi.fn(),
  sendInviteMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

vi.mock("@/actions/invitations/invitation", () => ({
  sendInvite: sendInviteMock,
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

const ROLES = [{ id: "22222222-2222-4222-8222-222222222222", name: "admin" }];

const fillAndSubmit = async (user: ReturnType<typeof userEvent.setup>) => {
  await user.type(screen.getByLabelText(/email/i), "teammate@company.com");
  await user.selectOptions(screen.getByRole("combobox"), ROLES[0].id);
  await user.click(screen.getByRole("button", { name: /send invitation/i }));
};

describe("SendInvitationForm", () => {
  beforeEach(() => {
    pushMock.mockReset();
    sendInviteMock.mockReset().mockResolvedValue({ data: { id: "inv-1" } });
  });

  it("navigates to the invitation details by default", async () => {
    // Given
    const user = userEvent.setup();
    render(<SendInvitationForm roles={ROLES} isSelectorDisabled={false} />);

    // When
    await fillAndSubmit(user);

    // Then
    await waitFor(() =>
      expect(pushMock).toHaveBeenCalledWith(
        "/invitations/check-details/?id=inv-1",
      ),
    );
    const formData = sendInviteMock.mock.calls[0]?.[0] as FormData;
    expect(formData.get("source")).toBeNull();
  });

  it("hands the new invitation to onSuccess and tags the source when given", async () => {
    // Given
    const user = userEvent.setup();
    const onSuccess = vi.fn();
    render(
      <SendInvitationForm
        roles={ROLES}
        isSelectorDisabled={false}
        source="onboarding"
        onSuccess={onSuccess}
      />,
    );

    // When
    await fillAndSubmit(user);

    // Then
    await waitFor(() => expect(onSuccess).toHaveBeenCalledWith("inv-1"));
    expect(pushMock).not.toHaveBeenCalled();
    const formData = sendInviteMock.mock.calls[0]?.[0] as FormData;
    expect(formData.get("source")).toBe("onboarding");
  });
});
