import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { pushMock, testProviderConnectionMock } = vi.hoisted(() => ({
  pushMock: vi.fn(),
  testProviderConnectionMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, back: vi.fn() }),
}));

vi.mock("@/actions/providers", () => ({
  deleteCredentials: vi.fn(),
}));

vi.mock("@/lib/provider-helpers", () => ({
  testProviderConnection: testProviderConnectionMock,
}));

import { CONNECTION_CHECK_STATUS } from "@/types/providers";

import {
  TestConnectionForm,
  type TestConnectionProviderData,
} from "./test-connection-form";

const providerData: TestConnectionProviderData = {
  data: {
    id: "provider-1",
    type: "providers",
    attributes: {
      uid: "111111111111",
      connection: { connected: false, last_checked_at: null },
      provider: "aws",
      alias: "Production",
      scanner_args: {},
    },
    relationships: {
      secret: { data: { type: "provider-secrets", id: "secret-1" } },
    },
  },
};

describe("TestConnectionForm", () => {
  beforeEach(() => {
    pushMock.mockReset();
    testProviderConnectionMock.mockReset();
  });

  it("advances on a confirmed successful connection", async () => {
    // Given
    testProviderConnectionMock.mockResolvedValue({
      status: CONNECTION_CHECK_STATUS.SUCCESS,
      error: null,
    });
    const onSuccess = vi.fn();
    const user = userEvent.setup();

    render(
      <TestConnectionForm
        searchParams={{ type: "aws", id: "provider-1", updated: "false" }}
        providerData={providerData}
        onSuccess={onSuccess}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /continue/i }));

    // Then
    expect(onSuccess).toHaveBeenCalledTimes(1);
    expect(
      screen.queryByText(/issue with your credentials/i),
    ).not.toBeInTheDocument();
  });

  it("shows a destructive failure message for a confirmed failed connection", async () => {
    // Given
    testProviderConnectionMock.mockResolvedValue({
      status: CONNECTION_CHECK_STATUS.FAILED,
      error: "Role trust policy mismatch.",
    });
    const user = userEvent.setup();

    render(
      <TestConnectionForm
        searchParams={{ type: "aws", id: "provider-1", updated: "false" }}
        providerData={providerData}
        onSuccess={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /continue/i }));

    // Then
    expect(screen.getByText("Role trust policy mismatch.")).toBeInTheDocument();
    expect(
      screen.getByText(/issue with your credentials/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /reset credentials/i }),
    ).toBeInTheDocument();
    // Announced to screen readers as soon as it appears, not only on focus.
    expect(screen.getByRole("status")).toHaveTextContent(
      "Role trust policy mismatch.",
    );
  });

  it("shows a neutral still-running message, not a failure, when the check is still pending", async () => {
    // Given: the wait was exhausted and the provider's stored state could not
    // confirm an outcome yet (the backend check is genuinely still running).
    testProviderConnectionMock.mockResolvedValue({
      status: CONNECTION_CHECK_STATUS.PENDING,
      error:
        "The connection test is still running. Refresh in a moment to see the result.",
    });
    const onSuccess = vi.fn();
    const user = userEvent.setup();

    render(
      <TestConnectionForm
        searchParams={{ type: "aws", id: "provider-1", updated: "false" }}
        providerData={providerData}
        onSuccess={onSuccess}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /continue/i }));

    // Then: the neutral message shows, but nothing reads as a credentials failure.
    expect(screen.getByText(/still running/i)).toBeInTheDocument();
    // Announced to screen readers, same as the failure banner.
    expect(screen.getByRole("status")).toHaveTextContent(/still running/i);
    expect(
      screen.queryByText(/issue with your credentials/i),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /reset credentials/i }),
    ).not.toBeInTheDocument();
    // Does not advance either -- the outcome is still unknown.
    expect(onSuccess).not.toHaveBeenCalled();
    expect(pushMock).not.toHaveBeenCalled();
    // The retry control is explicit about what pressing it does now: it is no
    // longer the first check, so "Continue" would be misleading.
    expect(
      screen.getByRole("button", { name: /check again/i }),
    ).toBeInTheDocument();
  });

  it("re-runs the check when 'Check again' is pressed on a still-pending result", async () => {
    // Given: the first attempt came back pending.
    testProviderConnectionMock.mockResolvedValueOnce({
      status: CONNECTION_CHECK_STATUS.PENDING,
      error: "The connection test is still running.",
    });
    const user = userEvent.setup();

    render(
      <TestConnectionForm
        searchParams={{ type: "aws", id: "provider-1", updated: "false" }}
        providerData={providerData}
        onSuccess={vi.fn()}
      />,
    );
    await user.click(screen.getByRole("button", { name: /continue/i }));
    expect(
      screen.getByRole("button", { name: /check again/i }),
    ).toBeInTheDocument();

    // When: pressing "Check again" resolves this time.
    testProviderConnectionMock.mockResolvedValueOnce({
      status: CONNECTION_CHECK_STATUS.SUCCESS,
      error: null,
    });
    await user.click(screen.getByRole("button", { name: /check again/i }));

    // Then
    expect(testProviderConnectionMock).toHaveBeenCalledTimes(2);
    expect(screen.queryByText(/still running/i)).not.toBeInTheDocument();
  });
});
