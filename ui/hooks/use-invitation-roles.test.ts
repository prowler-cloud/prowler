import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useInvitationRoles } from "./use-invitation-roles";

const { getInvitationRoles } = vi.hoisted(() => ({
  getInvitationRoles: vi.fn(),
}));

vi.mock("@/actions/invitations/roles", () => ({ getInvitationRoles }));

const ROLES = [
  { id: "11111111-1111-4111-8111-111111111111", name: "member" },
  { id: "22222222-2222-4222-8222-222222222222", name: "admin" },
];

describe("useInvitationRoles", () => {
  beforeEach(() => {
    getInvitationRoles.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("is unsettled until the roles arrive, then exposes them as loaded", async () => {
    getInvitationRoles.mockResolvedValue(ROLES);

    const { result } = renderHook(() => useInvitationRoles());

    expect(result.current).toBeNull();
    await waitFor(() => expect(result.current).toEqual(ROLES));
  });

  it("settles empty when the read fails", async () => {
    getInvitationRoles.mockRejectedValue(new Error("roles unavailable"));

    const { result } = renderHook(() => useInvitationRoles());

    await waitFor(() => expect(result.current).toEqual([]));
  });

  it("settles empty when the read never answers, and ignores a late answer", async () => {
    vi.useFakeTimers();
    let resolveLate: (roles: typeof ROLES) => void = () => {};
    getInvitationRoles.mockReturnValue(
      new Promise<typeof ROLES>((resolve) => {
        resolveLate = resolve;
      }),
    );

    const { result } = renderHook(() => useInvitationRoles());
    expect(result.current).toBeNull();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });
    expect(result.current).toEqual([]);

    await act(async () => {
      resolveLate(ROLES);
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current).toEqual([]);
  });
});
