import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { refreshMock, scanOnDemandMock } = vi.hoisted(() => ({
  refreshMock: vi.fn(),
  scanOnDemandMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    refresh: refreshMock,
  }),
}));

vi.mock("@/actions/scans", () => ({
  scanOnDemand: scanOnDemandMock,
}));

vi.mock("@/components/ui/toast", () => ({
  toast: vi.fn(),
}));

vi.mock("@/components/shadcn/modal", () => ({
  Modal: ({
    children,
    open,
    title,
  }: {
    children: React.ReactNode;
    open: boolean;
    title: string;
  }) =>
    open ? (
      <div role="dialog" aria-label={title}>
        {children}
      </div>
    ) : null,
}));

vi.mock("@/components/ui/entities", () => ({
  EntityInfo: ({
    entityAlias,
    entityId,
  }: {
    entityAlias?: string;
    entityId?: string;
  }) => <>{entityAlias || entityId}</>,
}));

vi.mock("@/components/shadcn", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/components/shadcn")>();

  return {
    ...actual,
    Select: ({
      children,
      onValueChange,
      value,
    }: {
      children: React.ReactNode;
      onValueChange: (value: string) => void;
      value: string;
    }) => (
      <select
        aria-label="Cloud Account"
        value={value}
        onChange={(event) => onValueChange(event.target.value)}
      >
        {children}
      </select>
    ),
    SelectContent: ({ children }: { children: React.ReactNode }) => children,
    SelectItem: ({
      children,
      value,
    }: {
      children: React.ReactNode;
      value: string;
    }) => <option value={value}>{children}</option>,
    SelectTrigger: ({ children }: { children: React.ReactNode }) => children,
    SelectValue: ({ children }: { children: React.ReactNode }) => children,
  };
});

import { LaunchScanModal } from "./launch-scan-modal";

const provider = {
  providerId: "provider-1",
  alias: "Production",
  providerType: "aws",
  uid: "123456789012",
  connected: true,
};

describe("LaunchScanModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });
  });

  it("submits scan note as scanName so the API stores it as the scan alias", async () => {
    const user = userEvent.setup();

    render(
      <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
    );

    await user.selectOptions(
      screen.getByLabelText("Cloud Account"),
      provider.providerId,
    );
    await user.type(screen.getByLabelText("Scan Note"), "Production audit");
    await user.click(screen.getByRole("button", { name: /launch scan/i }));

    await waitFor(() => expect(scanOnDemandMock).toHaveBeenCalled());

    const formData = scanOnDemandMock.mock.calls[0][0] as FormData;
    expect(formData.get("providerId")).toBe(provider.providerId);
    expect(formData.get("scanName")).toBe("Production audit");
    expect(formData.get("scanNote")).toBeNull();
  });
});
