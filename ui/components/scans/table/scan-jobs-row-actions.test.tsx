import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ScanProps } from "@/types";

import { ScanJobsRowActions } from "./scan-jobs-row-actions";

const { downloadScanZipMock, getTaskMock, pushMock, toastMock } = vi.hoisted(
  () => ({
    downloadScanZipMock: vi.fn(),
    getTaskMock: vi.fn(),
    pushMock: vi.fn(),
    toastMock: vi.fn(),
  }),
);

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: pushMock,
  }),
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({ toast: toastMock }),
}));

vi.mock("@/actions/task", () => ({
  getTask: getTaskMock,
}));

vi.mock("@/lib/helper", () => ({
  downloadScanZip: downloadScanZipMock,
}));

vi.mock("@/lib/date-utils", () => ({
  toLocalDateString: (value: string | null | undefined) =>
    value ? "2026-01-01" : undefined,
}));

vi.mock("@/components/scans/edit-alias-modal", () => ({
  EditAliasModal: ({
    open,
    currentAlias,
  }: {
    open: boolean;
    currentAlias: string;
  }) =>
    open ? (
      <div role="dialog" aria-label="Edit Alias">
        Editing {currentAlias}
      </div>
    ) : null,
}));

const makeScan = (
  overrides: Partial<ScanProps["attributes"]> = {},
): ScanProps => ({
  type: "scans",
  id: "scan-1",
  attributes: {
    name: "Production scan",
    trigger: "scheduled",
    state: "scheduled",
    unique_resource_count: 0,
    progress: 0,
    scanner_args: null,
    duration: 0,
    started_at: "",
    inserted_at: "",
    completed_at: "",
    scheduled_at: "",
    next_scan_at: "",
    ...overrides,
  },
  relationships: {
    provider: { data: { type: "providers", id: "provider-1" } },
    task: { data: { type: "tasks", id: "task-1" } },
  },
});

describe("ScanJobsRowActions", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.clearAllMocks();
  });

  it("opens the Edit modal seeded with the current scan name", async () => {
    // Given
    const user = userEvent.setup();

    render(<ScanJobsRowActions scan={makeScan()} />);

    // When
    await user.click(
      screen.getByRole("button", { name: /open actions menu/i }),
    );
    await user.click(screen.getByRole("menuitem", { name: /^edit$/i }));

    // Then
    expect(
      screen.getByRole("dialog", { name: /edit alias/i }),
    ).toHaveTextContent("Editing Production scan");
  });

  it("does not render the legacy Edit Scan Schedule option", async () => {
    // Given
    const user = userEvent.setup();

    render(<ScanJobsRowActions scan={makeScan()} />);

    // When
    await user.click(
      screen.getByRole("button", { name: /open actions menu/i }),
    );

    // Then
    expect(
      screen.queryByRole("menuitem", { name: /edit scan schedule/i }),
    ).not.toBeInTheDocument();
  });

  it("does not render cancel scan while the scan cancellation API is missing", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
    const user = userEvent.setup();

    render(<ScanJobsRowActions scan={makeScan()} />);

    // When
    await user.click(
      screen.getByRole("button", { name: /open actions menu/i }),
    );

    // Then
    expect(
      screen.queryByRole("menuitem", { name: /cancel scan/i }),
    ).not.toBeInTheDocument();
  });

  it("links completed scans to compliance from the actions menu", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <ScanJobsRowActions
        scan={makeScan({
          state: "completed",
          completed_at: "2026-01-01T10:05:00Z",
        })}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: /open actions menu/i }),
    );
    await user.click(
      screen.getByRole("menuitem", { name: /view compliance/i }),
    );

    // Then
    expect(pushMock).toHaveBeenCalledWith("/compliance?scanId=scan-1");
  });

  it("renames the completed scan report download action", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <ScanJobsRowActions
        scan={makeScan({
          state: "completed",
          completed_at: "2026-01-01T10:05:00Z",
        })}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: /open actions menu/i }),
    );

    // Then
    expect(
      screen.getByRole("menuitem", { name: /download scan reports/i }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("menuitem", { name: /download findings/i }),
    ).not.toBeInTheDocument();
  });

  it("links completed scans to filtered findings", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <ScanJobsRowActions
        scan={makeScan({
          state: "completed",
          completed_at: "2026-01-01T10:05:00Z",
        })}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: /open actions menu/i }),
    );
    await user.click(screen.getByRole("menuitem", { name: /view findings/i }));

    // Then
    expect(pushMock).toHaveBeenCalledWith(
      "/findings?filter[scan]=scan-1&filter[inserted_at]=2026-01-01&filter[status__in]=FAIL",
    );
  });

  it("triggers downloadScanZip with the scan id when downloading reports", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <ScanJobsRowActions
        scan={makeScan({
          state: "completed",
          completed_at: "2026-01-01T10:05:00Z",
        })}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: /open actions menu/i }),
    );
    await user.click(
      screen.getByRole("menuitem", { name: /download scan reports/i }),
    );

    // Then
    expect(downloadScanZipMock).toHaveBeenCalledWith("scan-1", toastMock);
  });

  it("opens failed scan error details from the actions menu", async () => {
    // Given
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    getTaskMock.mockResolvedValue({
      data: {
        attributes: {
          result: {
            exc_type: "ValidationError",
            exc_message: ["Missing cloud credentials", "Retry scan setup"],
          },
        },
      },
    });

    render(
      <ScanJobsRowActions
        scan={makeScan({
          state: "failed",
          completed_at: "2026-01-01T10:05:00Z",
        })}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: /open actions menu/i }),
    );
    await user.click(
      screen.getByRole("menuitem", { name: /view error details/i }),
    );

    // Then
    expect(getTaskMock).toHaveBeenCalledWith("task-1");
    expect(
      await screen.findByRole("dialog", { name: /scan error details/i }),
    ).toBeInTheDocument();
    expect(screen.getByText("ValidationError")).toBeInTheDocument();
    expect(screen.getByText(/Missing cloud credentials/)).toBeInTheDocument();
    expect(screen.getByText(/Retry scan setup/)).toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: /copy error details/i }),
    );
    expect(writeText).toHaveBeenCalledWith(
      "ErrorType: ValidationError\nError: Missing cloud credentials\nRetry scan setup",
    );
  });

  it("does not show error details for non-failed scans", async () => {
    // Given
    const user = userEvent.setup();

    render(<ScanJobsRowActions scan={makeScan({ state: "completed" })} />);

    // When
    await user.click(
      screen.getByRole("button", { name: /open actions menu/i }),
    );

    // Then
    expect(
      screen.queryByRole("menuitem", { name: /view error details/i }),
    ).not.toBeInTheDocument();
  });
});
