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

  it("is always green and pulsing", () => {
    render(<RecheckResourceIconButton target={target} />);

    const button = screen.getByRole("button", { name: RECHECK_RESOURCE_LABEL });
    expect(button.className).toContain("text-button-primary");
    expect(button.className).toContain("animate-pulse");
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
