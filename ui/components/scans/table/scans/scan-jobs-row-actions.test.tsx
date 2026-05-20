import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ScanProps } from "@/types";

import { ScanJobsRowActions } from "./scan-jobs-row-actions";

const { pushMock, toastMock } = vi.hoisted(() => ({
  pushMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: pushMock,
  }),
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: toastMock }),
}));

vi.mock("@/lib/helper", () => ({
  downloadScanZip: vi.fn(),
}));

const makeScan = (): ScanProps => ({
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

  it("shows the Prowler Cloud tooltip for edit schedule outside Cloud", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    const user = userEvent.setup();

    render(<ScanJobsRowActions scan={makeScan()} />);

    // When
    await user.click(
      screen.getByRole("button", { name: /open actions menu/i }),
    );
    const editScheduleAction = screen.getByRole("menuitem", {
      name: /edit scan schedule/i,
    });
    await user.hover(editScheduleAction);

    // Then
    expect(editScheduleAction).toHaveAttribute("data-disabled");
    expect(
      await screen.findAllByText("Available in Prowler Cloud"),
    ).not.toHaveLength(0);
  });

  it("does not show the Prowler Cloud tooltip for edit schedule in Cloud", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
    const user = userEvent.setup();

    render(<ScanJobsRowActions scan={makeScan()} />);

    // When
    await user.click(
      screen.getByRole("button", { name: /open actions menu/i }),
    );
    const editScheduleAction = screen.getByRole("menuitem", {
      name: /edit scan schedule/i,
    });
    await user.hover(editScheduleAction);

    // Then
    expect(editScheduleAction).toHaveAttribute("data-disabled");
    expect(
      screen.queryByText("Available in Prowler Cloud"),
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
});
