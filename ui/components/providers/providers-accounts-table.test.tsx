import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { MetaDataProps } from "@/types";
import { SCAN_SCHEDULE_CAPABILITY } from "@/types/schedules";

const { getColumnProvidersMock } = vi.hoisted(() => ({
  getColumnProvidersMock: vi.fn((..._args: unknown[]) => []),
}));

vi.mock("@/components/ui/table", () => ({
  DataTable: () => <div data-testid="providers-data-table" />,
}));

vi.mock("./table", () => ({
  getColumnProviders: (...args: unknown[]) => getColumnProvidersMock(...args),
}));

import { ProvidersAccountsTable } from "./providers-accounts-table";

const metadata: MetaDataProps = {
  pagination: { page: 1, pages: 1, count: 0, itemsPerPage: [10] },
  version: "latest",
};

describe("ProvidersAccountsTable", () => {
  it("passes scan schedule capability to provider row action columns", () => {
    // Given/When
    render(
      <ProvidersAccountsTable
        isCloud
        metadata={metadata}
        rows={[]}
        scanScheduleCapability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByTestId("providers-data-table")).toBeInTheDocument();
    expect(getColumnProvidersMock).toHaveBeenCalledWith(
      expect.any(Object),
      [],
      expect.any(Function),
      expect.any(Function),
      expect.any(Function),
      SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY,
    );
  });
});
