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
});
