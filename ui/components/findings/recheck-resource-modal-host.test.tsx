import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { RecheckResourceModalMock } = vi.hoisted(() => ({
  RecheckResourceModalMock: vi.fn(
    (_props: {
      isOpen: boolean;
      onOpenChange: (open: boolean) => void;
      target: unknown;
    }) => null,
  ),
}));

vi.mock("./recheck-resource-modal", () => ({
  RecheckResourceModal: RecheckResourceModalMock,
}));

import { usePartialScanStore } from "@/store/partial-scan/store";

import { RecheckResourceModalHost } from "./recheck-resource-modal-host";

const target = {
  providerId: "provider-1",
  providerUid: "123456789012",
  providerType: "aws",
  resourceUid: "arn:aws:s3:::bucket",
  resourceName: "bucket",
};

describe("RecheckResourceModalHost", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    usePartialScanStore.getState().closePartialScan();
  });

  it("renders nothing without an active target", () => {
    render(<RecheckResourceModalHost />);

    expect(RecheckResourceModalMock).not.toHaveBeenCalled();
  });

  it("mounts the modal for the active target and closes through the store", () => {
    usePartialScanStore.getState().openPartialScan(target);

    render(<RecheckResourceModalHost />);

    expect(RecheckResourceModalMock).toHaveBeenCalledWith(
      expect.objectContaining({ isOpen: true, target }),
      undefined,
    );

    RecheckResourceModalMock.mock.calls[0][0].onOpenChange(false);

    expect(usePartialScanStore.getState().activeTarget).toBeNull();
  });
});
