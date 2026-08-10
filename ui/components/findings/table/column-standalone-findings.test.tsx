import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
}));

// CustomLink pulls the "@/lib" barrel (and next-auth with it) into the unit env.
vi.mock("@/components/shadcn/custom/custom-link", () => ({
  CustomLink: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock("@/components/findings/mute-findings-modal", () => ({
  MuteFindingsModal: () => null,
}));

vi.mock("@/components/findings/send-to-jira-modal", () => ({
  SendToJiraModal: () => null,
}));

vi.mock("@/components/icons/services/IconServices", () => ({
  JiraIcon: () => null,
}));

vi.mock("@/components/shadcn/dropdown", () => ({
  ActionDropdown: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  ActionDropdownItem: ({
    label,
    onSelect,
    disabled,
  }: {
    label: string;
    onSelect?: () => void;
    disabled?: boolean;
  }) => (
    <button disabled={disabled} onClick={onSelect}>
      {label}
    </button>
  ),
}));

vi.mock("@/components/shadcn/spinner/spinner", () => ({
  Spinner: () => null,
}));

vi.mock("@/components/shadcn/entities", () => ({
  DateWithTime: ({ dateTime }: { dateTime: string | null }) => (
    <time>{dateTime ?? "-"}</time>
  ),
  EntityInfo: () => null,
}));

vi.mock("@/components/shadcn/table", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
  SeverityBadge: ({ severity }: { severity: string }) => (
    <span>{severity}</span>
  ),
  StatusFindingBadge: ({ status }: { status: string }) => <span>{status}</span>,
}));

vi.mock("@/components/shadcn/select/select", () => ({
  Select: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  SelectContent: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  SelectItem: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  SelectTrigger: ({
    children,
    disabled,
    "aria-label": ariaLabel,
  }: {
    children: ReactNode;
    disabled?: boolean;
    "aria-label"?: string;
  }) => (
    <button aria-label={ariaLabel} disabled={disabled}>
      {children}
    </button>
  ),
}));

vi.mock("@/components/shadcn/tooltip", () => ({
  Tooltip: ({ children }: { children: ReactNode }) => <>{children}</>,
  TooltipContent: ({ children }: { children: ReactNode }) => (
    <span>{children}</span>
  ),
  TooltipTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("@/lib/region-flags", () => ({
  getRegionFlag: () => "",
}));

vi.mock("./finding-detail-drawer", () => ({
  FindingDetailDrawer: ({ trigger }: { trigger: ReactNode }) => <>{trigger}</>,
}));

vi.mock("./notification-indicator", () => ({
  DeltaValues: { NEW: "new", CHANGED: "changed", NONE: "none" },
  NotificationIndicator: () => null,
}));

vi.mock("./provider-icon-cell", () => ({
  ProviderIconCell: () => null,
}));

import { getStandaloneFindingColumns } from "./column-standalone-findings";

describe("column-standalone-findings", () => {
  it("should render Triage and Actions as the last visible data columns without Notes", () => {
    // Given
    const columns = getStandaloneFindingColumns({ includeUpdatedAt: true });

    // When
    const columnIds = columns.map(
      (column) =>
        (column as { id?: string; accessorKey?: string }).id ??
        (column as { id?: string; accessorKey?: string }).accessorKey,
    );

    // Then
    expect(columnIds.slice(-2)).toEqual(["triage", "actions"]);
    expect(columnIds).not.toContain("notes");
    expect(
      (columns.at(-1) as { id?: string; size?: number } | undefined)?.size,
    ).toBe(56);
  });
});
