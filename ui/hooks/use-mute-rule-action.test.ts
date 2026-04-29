import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { toastMock } = vi.hoisted(() => ({
  toastMock: vi.fn(),
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({
    toast: toastMock,
  }),
}));

import { useMuteRuleAction } from "./use-mute-rule-action";

describe("useMuteRuleAction", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows a success toast and runs the success callback", async () => {
    const onSuccess = vi.fn();
    const setState = vi.fn();
    const { result } = renderHook(() => useMuteRuleAction());

    act(() => {
      result.current.runAction(
        async () => ({ success: "Mute rule updated successfully!" }),
        {
          setState,
          onSuccess,
        },
      );
    });

    await waitFor(() => {
      expect(setState).toHaveBeenCalledWith({
        success: "Mute rule updated successfully!",
      });
      expect(toastMock).toHaveBeenCalledWith({
        title: "Success",
        description: "Mute rule updated successfully!",
      });
      expect(onSuccess).toHaveBeenCalledTimes(1);
    });
  });

  it("allows overriding the success message", async () => {
    const { result } = renderHook(() => useMuteRuleAction());

    act(() => {
      result.current.runAction(
        async () => ({ success: "Server success message" }),
        {
          successMessage:
            "Mute rule created. It may take a few minutes for all findings to update.",
        },
      );
    });

    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith({
        title: "Success",
        description:
          "Mute rule created. It may take a few minutes for all findings to update.",
      });
    });
  });

  it("shows an error toast when the action returns a general error", async () => {
    const onError = vi.fn();
    const { result } = renderHook(() => useMuteRuleAction());

    act(() => {
      result.current.runAction(
        async () => ({ errors: { general: "Delete failed" } }),
        {
          onError,
        },
      );
    });

    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith({
        variant: "destructive",
        title: "Error",
        description: "Delete failed",
      });
      expect(onError).toHaveBeenCalledWith("Delete failed");
    });
  });

  it("updates form state without showing a toast for field-level validation errors", async () => {
    const setState = vi.fn();
    const { result } = renderHook(() => useMuteRuleAction());

    act(() => {
      result.current.runAction(
        async () => ({ errors: { name: "Name is required" } }),
        {
          setState,
        },
      );
    });

    await waitFor(() => {
      expect(setState).toHaveBeenCalledWith({
        errors: { name: "Name is required" },
      });
    });

    expect(toastMock).not.toHaveBeenCalled();
  });
});
