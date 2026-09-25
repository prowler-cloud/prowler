import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { isCloudMock, hasPermissionMock } = vi.hoisted(() => ({
  isCloudMock: vi.fn(() => true),
  hasPermissionMock: vi.fn(() => true),
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: isCloudMock,
}));

vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ hasPermission: hasPermissionMock }),
}));

import { usePartialScanHintStore } from "@/store/partial-scan/hint-store";
import { usePartialScanStore } from "@/store/partial-scan/store";

import { RECHECK_RESOURCE_LABEL } from "./recheck-resource-action-item";
import { RecheckResourceIconButton } from "./recheck-resource-icon-button";

const target = {
  providerUid: "123456789012",
  providerType: "aws",
  providerAlias: "prod",
  resourceUid: "arn:aws:s3:::bucket",
  resourceName: "bucket",
};

describe("RecheckResourceIconButton", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    isCloudMock.mockReturnValue(true);
    hasPermissionMock.mockReturnValue(true);
    usePartialScanStore.getState().closePartialScan();
    usePartialScanHintStore.setState({ hasSeenRecheckHint: false });
  });

  it("pulses until a re-check has been opened once, then settles", async () => {
    // Like the navbar bell: attention while undiscovered, calm afterwards.
    const user = userEvent.setup();
    render(<RecheckResourceIconButton target={target} />);
    const button = screen.getByRole("button", { name: RECHECK_RESOURCE_LABEL });

    expect(button).toHaveAttribute("data-attention", "true");
    expect(button.className).toContain("animate-pulse");

    await user.click(button);

    expect(usePartialScanHintStore.getState().hasSeenRecheckHint).toBe(true);
    expect(button).not.toHaveAttribute("data-attention");
    expect(button.className).not.toContain("animate-pulse");
  });

  it("stays calm when the hint was already acknowledged", () => {
    usePartialScanHintStore.setState({ hasSeenRecheckHint: true });
    render(<RecheckResourceIconButton target={target} />);

    expect(
      screen.getByRole("button", { name: RECHECK_RESOURCE_LABEL }),
    ).not.toHaveAttribute("data-attention");
  });

  it("opens the confirmation for the resource without triggering the row", async () => {
    // The button sits inside a clickable row that opens the detail drawer.
    const user = userEvent.setup();
    const onRowClick = vi.fn();
    render(
      <div onClick={onRowClick}>
        <RecheckResourceIconButton target={target} />
      </div>,
    );

    await user.click(
      screen.getByRole("button", { name: RECHECK_RESOURCE_LABEL }),
    );

    expect(usePartialScanStore.getState().activeTarget).toEqual(target);
    expect(onRowClick).not.toHaveBeenCalled();
  });

  it("is hidden outside Prowler Cloud", () => {
    isCloudMock.mockReturnValue(false);
    render(<RecheckResourceIconButton target={target} />);

    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("is hidden without the manage_scans permission", () => {
    hasPermissionMock.mockReturnValue(false);
    render(<RecheckResourceIconButton target={target} />);

    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
