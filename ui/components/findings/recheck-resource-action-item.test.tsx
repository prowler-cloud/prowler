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

vi.mock("@/components/shadcn/dropdown", () => ({
  ActionDropdownItem: ({
    label,
    onSelect,
  }: {
    label: string;
    onSelect?: () => void;
  }) => (
    <button type="button" onClick={onSelect}>
      {label}
    </button>
  ),
}));

import { usePartialScanStore } from "@/store/partial-scan/store";

import {
  RECHECK_RESOURCE_LABEL,
  RecheckResourceActionItem,
} from "./recheck-resource-action-item";

const target = {
  providerId: "provider-1",
  providerUid: "123456789012",
  providerType: "aws",
  providerAlias: "prod",
  resourceUid: "arn:aws:s3:::bucket",
  resourceName: "bucket",
};

describe("RecheckResourceActionItem", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    isCloudMock.mockReturnValue(true);
    hasPermissionMock.mockReturnValue(true);
    usePartialScanStore.getState().closePartialScan();
  });

  it("opens the confirmation with the resource as target", async () => {
    const user = userEvent.setup();
    render(<RecheckResourceActionItem target={target} />);

    await user.click(
      screen.getByRole("button", { name: RECHECK_RESOURCE_LABEL }),
    );

    expect(usePartialScanStore.getState().activeTarget).toEqual(target);
  });

  it("is hidden outside Prowler Cloud", () => {
    isCloudMock.mockReturnValue(false);
    render(<RecheckResourceActionItem target={target} />);

    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("is hidden without the manage_scans permission", () => {
    hasPermissionMock.mockReturnValue(false);
    render(<RecheckResourceActionItem target={target} />);

    expect(hasPermissionMock).toHaveBeenCalledWith("manage_scans");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("is hidden when the row cannot name a resource", () => {
    render(
      <RecheckResourceActionItem target={{ ...target, resourceUid: "-" }} />,
    );

    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
