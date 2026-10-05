import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useRef, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getProviderDisplayName } from "@/types/providers";

import { AWS_CONNECT_ACTION_KIND, type AwsConnectUiState } from "../aws/types";

import { InviteTeammatePanel } from "./invite-teammate-panel";

const { getInvitationRoles, sendInvite, toastMock } = vi.hoisted(() => ({
  getInvitationRoles: vi.fn(),
  sendInvite: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/invitations/roles", () => ({ getInvitationRoles }));
vi.mock("@/actions/invitations/invitation", () => ({ sendInvite }));
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

const FORM_ID = "invite-teammate-test-form";
const ROLES = [
  { id: "11111111-1111-4111-8111-111111111111", name: "member" },
  { id: "22222222-2222-4222-8222-222222222222", name: "admin" },
];
const SENT = {
  data: {
    id: "inv-1",
    attributes: { email: "teammate@company.com", token: "abc123DEF45678" },
  },
};

// Stands in for the wizard footer: the panel only publishes its UI state.
function Harness({
  onUiState,
  onBusyChange,
}: {
  onUiState: (state: AwsConnectUiState) => void;
  onBusyChange: (isBusy: boolean) => void;
}) {
  const [uiState, setUiState] = useState<AwsConnectUiState | null>(null);
  // Stable like the wizard's own setter: the panel keys an effect on it.
  const handleUiState = useRef((state: AwsConnectUiState) => {
    setUiState(state);
    onUiState(state);
  }).current;
  return (
    <>
      <InviteTeammatePanel
        providerType="aws"
        formId={FORM_ID}
        onUiStateChange={handleUiState}
        onBusyChange={onBusyChange}
      />
      {uiState?.showAction && (
        <button
          type="submit"
          form={FORM_ID}
          disabled={uiState.actionDisabled || uiState.isLoading}
        >
          {uiState.actionLabel}
        </button>
      )}
    </>
  );
}

function renderPanel() {
  const onUiState = vi.fn();
  const onBusyChange = vi.fn();
  render(<Harness onUiState={onUiState} onBusyChange={onBusyChange} />);
  return { onUiState, onBusyChange, user: userEvent.setup() };
}

const lastUiState = (onUiState: ReturnType<typeof vi.fn>) =>
  onUiState.mock.calls.at(-1)?.[0] as AwsConnectUiState;

async function fillAndSend(user: ReturnType<typeof userEvent.setup>) {
  await user.type(
    await screen.findByRole("textbox", { name: /Teammate email/ }),
    "teammate@company.com",
  );
  const send = screen.getByRole("button", { name: "Send invitation" });
  await waitFor(() => expect(send).toBeEnabled());
  await user.click(send);
}

describe("InviteTeammatePanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getInvitationRoles.mockResolvedValue(ROLES);
    sendInvite.mockResolvedValue(SENT);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("holds the footer on a disabled Send invitation while the roles load", () => {
    // Given: roles that have not answered yet.
    getInvitationRoles.mockReturnValue(new Promise(() => {}));

    // When
    const { onUiState } = renderPanel();

    // Then
    expect(lastUiState(onUiState)).toMatchObject({
      showAction: true,
      actionLabel: "Send invitation",
      actionDisabled: true,
      actionKind: AWS_CONNECT_ACTION_KIND.SUBMIT,
    });
    expect(screen.getByRole("status")).toHaveTextContent(/Loading roles/);
  });

  it("offers the roles admin first, preselected, and gates Send on a valid email", async () => {
    // When
    const { onUiState } = renderPanel();

    // Then
    const select = await screen.findByRole("combobox", {
      name: "Select a role",
    });
    expect(select).toHaveValue(ROLES[1].id);
    expect(
      screen.getAllByRole("option").map((option) => option.textContent),
    ).toEqual(["Select a role", "admin", "member"]);
    expect(lastUiState(onUiState)).toMatchObject({
      actionLabel: "Send invitation",
      actionDisabled: true,
    });
  });

  it("sends the invitation tagged as coming from the provider connection and shows the link", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    const { onUiState, onBusyChange, user } = renderPanel();

    // When
    await fillAndSend(user);

    // Then: the API got the form, the user gets the link to share.
    const formData = sendInvite.mock.calls[0]?.[0] as FormData;
    expect(formData.get("email")).toBe("teammate@company.com");
    expect(formData.get("role")).toBe(ROLES[1].id);
    expect(formData.get("source")).toBe("provider_connect");
    expect(
      await screen.findByText("Invitation sent to teammate@company.com"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        `${window.location.origin}/invitation/accept?invitation_token=abc123DEF45678`,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Prowler does not send emails/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        new RegExp(`connect the ${getProviderDisplayName("aws")} account`),
      ),
    ).toBeInTheDocument();
    // The footer closes the wizard from here, and the step is no longer busy.
    expect(lastUiState(onUiState)).toMatchObject({
      actionLabel: "Done",
      actionDisabled: false,
      actionKind: AWS_CONNECT_ACTION_KIND.CLOSE,
    });
    expect(onBusyChange).toHaveBeenLastCalledWith(false);
    expect(onBusyChange).toHaveBeenCalledWith(true);
  });

  it("tells a Cloud user the invitation was emailed too", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const { user } = renderPanel();

    // When
    await fillAndSend(user);

    // Then
    expect(
      await screen.findByText(/We have emailed them the invitation/),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/Prowler does not send emails/),
    ).not.toBeInTheDocument();
  });

  it("keeps the form up with the field error when the API rejects the email", async () => {
    // Given
    sendInvite.mockResolvedValue({
      errors: [
        {
          detail: "This email has already been invited.",
          source: { pointer: "/data/attributes/email" },
        },
      ],
    });
    const { onUiState, user } = renderPanel();

    // When
    await fillAndSend(user);

    // Then
    expect(
      await screen.findByText("This email has already been invited."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Invitation sent/)).not.toBeInTheDocument();
    expect(lastUiState(onUiState)).toMatchObject({
      actionLabel: "Send invitation",
      actionKind: AWS_CONNECT_ACTION_KIND.SUBMIT,
    });
  });

  it("stays on the form with a toast when the action resolves without an invitation", async () => {
    // Given: a 5xx makes the action resolve undefined.
    sendInvite.mockResolvedValue(undefined);
    const { user } = renderPanel();

    // When
    await fillAndSend(user);

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" }),
      ),
    );
    expect(screen.queryByText(/Invitation sent/)).not.toBeInTheDocument();
    expect(
      screen.getByRole("textbox", { name: /Teammate email/ }),
    ).toBeInTheDocument();
  });

  it("explains and hides the action when the roles cannot be loaded", async () => {
    // Given
    getInvitationRoles.mockRejectedValue(new Error("roles unavailable"));

    // When
    const { onUiState } = renderPanel();

    // Then
    expect(
      await screen.findByText(/Roles could not be loaded right now/),
    ).toBeInTheDocument();
    expect(lastUiState(onUiState)).toMatchObject({ showAction: false });
    expect(
      screen.queryByRole("button", { name: "Send invitation" }),
    ).not.toBeInTheDocument();
  });
});
