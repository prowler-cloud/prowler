import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { RealtimeAction } from "@/app/(prowler)/realtime/_types";

import { RevertActionButton } from "./revert-action-button";

const actions = vi.hoisted(() => ({ revertRealtimeAction: vi.fn() }));
const router = vi.hoisted(() => ({ refresh: vi.fn() }));
const toast = vi.hoisted(() => vi.fn());

vi.mock("@/app/(prowler)/realtime/_actions", () => actions);
vi.mock("next/navigation", () => ({ useRouter: () => router }));
vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({ toast }),
}));

const action: RealtimeAction = {
  id: "0f1c5a3e-7b2d-4d4c-9b7a-3c1e2f4a5b6c",
  provider_id: "provider-1",
  detection_id: null,
  kind: "self_fix",
  status: "fixed_verified",
  check_id: "s3_bucket_level_public_access_block",
  resource_uid: "marketing-assets",
  region: "us-east-1",
  severity: "high",
  summary: "Public access block restored",
  pr_url: "",
  branch: "",
  revertible: true,
  inserted_at: "2026-11-03T10:00:00Z",
};

describe("RevertActionButton", () => {
  beforeEach(() => {
    actions.revertRealtimeAction.mockReset();
    router.refresh.mockReset();
    toast.mockReset();
  });

  it("reverts only after the confirmation, then refreshes", async () => {
    actions.revertRealtimeAction.mockResolvedValue({ ok: true, data: action });
    const user = userEvent.setup();
    render(<RevertActionButton action={action} canWrite demo={false} />);

    await user.click(screen.getByRole("button", { name: "Revert" }));
    expect(actions.revertRealtimeAction).not.toHaveBeenCalled();
    expect(screen.getByText("Revert this fix?")).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: "Revert", hidden: false }),
    );
    await waitFor(() =>
      expect(actions.revertRealtimeAction).toHaveBeenCalledWith(action.id),
    );
    expect(router.refresh).toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Fix reverted" }),
    );
  });

  it("keeps the fix when the person backs out", async () => {
    const user = userEvent.setup();
    render(<RevertActionButton action={action} canWrite demo={false} />);

    await user.click(screen.getByRole("button", { name: "Revert" }));
    await user.click(screen.getByRole("button", { name: "Keep the fix" }));
    expect(actions.revertRealtimeAction).not.toHaveBeenCalled();
    expect(screen.queryByText("Revert this fix?")).not.toBeInTheDocument();
  });

  it("shows AWS's reason when the revert is refused", async () => {
    actions.revertRealtimeAction.mockResolvedValue({
      ok: false,
      status: 409,
      error: "The change could not be reverted: AccessDenied",
    });
    const user = userEvent.setup();
    render(<RevertActionButton action={action} canWrite demo={false} />);

    await user.click(screen.getByRole("button", { name: "Revert" }));
    await user.click(screen.getByRole("button", { name: "Revert" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          description: "The change could not be reverted: AccessDenied",
        }),
      ),
    );
    expect(router.refresh).not.toHaveBeenCalled();
  });

  it("is disabled without the permission", () => {
    render(
      <RevertActionButton action={action} canWrite={false} demo={false} />,
    );
    expect(screen.getByRole("button", { name: "Revert" })).toBeDisabled();
  });
});
