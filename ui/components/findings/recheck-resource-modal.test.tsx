import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { createPartialScanMock, getProvidersMock, refreshMock, toastMock } =
  vi.hoisted(() => ({
    createPartialScanMock: vi.fn(),
    getProvidersMock: vi.fn(),
    refreshMock: vi.fn(),
    toastMock: vi.fn(),
  }));

vi.mock("@/actions/scans", () => ({
  createPartialScan: createPartialScanMock,
}));

vi.mock("@/actions/providers", () => ({
  getProviders: getProvidersMock,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: refreshMock }),
}));

vi.mock("@/components/shadcn/toast", () => ({
  toast: toastMock,
  ToastAction: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock("@/components/shadcn/modal", () => ({
  Modal: ({
    open,
    title,
    children,
  }: {
    open: boolean;
    title: string;
    children: React.ReactNode;
  }) =>
    open ? (
      <div role="dialog" aria-label={title}>
        {children}
      </div>
    ) : null,
}));

import {
  PROVIDER_NOT_FOUND_ERROR,
  RECHECK_RESOURCE_SUBMIT_LABEL,
  RecheckResourceModal,
} from "./recheck-resource-modal";

const target = {
  providerId: "provider-1",
  providerUid: "123456789012",
  providerType: "aws",
  providerAlias: "prod",
  resourceUid: "arn:aws:s3:::bucket",
  resourceName: "bucket",
};

const submit = async () => {
  const user = userEvent.setup();
  await user.click(
    screen.getByRole("button", { name: RECHECK_RESOURCE_SUBMIT_LABEL }),
  );
};

describe("RecheckResourceModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    createPartialScanMock.mockResolvedValue({ data: { id: "scan-1" } });
  });

  it("launches a partial scan for the one resource and closes", async () => {
    const onOpenChange = vi.fn();
    render(
      <RecheckResourceModal
        isOpen
        onOpenChange={onOpenChange}
        target={target}
      />,
    );

    await submit();

    expect(createPartialScanMock).toHaveBeenCalledWith({
      providerId: "provider-1",
      resourceUids: ["arn:aws:s3:::bucket"],
    });
    expect(getProvidersMock).not.toHaveBeenCalled();
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Re-check launched" }),
    );
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(refreshMock).toHaveBeenCalled();
  });

  it("resolves the provider id from its uid and type when the row lacks it", async () => {
    getProvidersMock.mockResolvedValue({
      data: [
        { id: "aws-1", attributes: { uid: "123456789012", provider: "aws" } },
      ],
    });
    const { providerId: _omitted, ...rowTarget } = target;
    render(
      <RecheckResourceModal isOpen onOpenChange={vi.fn()} target={rowTarget} />,
    );

    await submit();

    expect(getProvidersMock).toHaveBeenCalledWith({
      filters: { "filter[uid]": "123456789012", "filter[provider]": "aws" },
    });
    expect(createPartialScanMock).toHaveBeenCalledWith({
      providerId: "aws-1",
      resourceUids: ["arn:aws:s3:::bucket"],
    });
  });

  it("explains when the provider cannot be found and launches nothing", async () => {
    getProvidersMock.mockResolvedValue({ data: [] });
    const { providerId: _omitted, ...rowTarget } = target;
    render(
      <RecheckResourceModal isOpen onOpenChange={vi.fn()} target={rowTarget} />,
    );

    await submit();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      PROVIDER_NOT_FOUND_ERROR,
    );
    expect(createPartialScanMock).not.toHaveBeenCalled();
  });

  it("keeps the modal open and shows the API reason when the re-check is refused", async () => {
    // The 409 detail already tells the user what to do, so it is shown verbatim.
    createPartialScanMock.mockResolvedValue({
      error:
        "A scan is already running for this provider. Re-check these resources once it finishes.",
      status: 409,
    });
    const onOpenChange = vi.fn();
    render(
      <RecheckResourceModal
        isOpen
        onOpenChange={onOpenChange}
        target={target}
      />,
    );

    await submit();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "A scan is already running for this provider.",
    );
    expect(onOpenChange).not.toHaveBeenCalled();
    expect(toastMock).not.toHaveBeenCalled();
    expect(refreshMock).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: RECHECK_RESOURCE_SUBMIT_LABEL }),
      ).toBeEnabled(),
    );
  });
});
