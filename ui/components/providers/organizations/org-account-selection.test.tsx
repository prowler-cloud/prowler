import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { APPLY_STATUS } from "@/types/organizations";

import { OrgAccountSelection } from "./org-account-selection";

const { useOrgAccountSelectionFlowMock, handleTreeSelectionChangeMock } =
  vi.hoisted(() => ({
    useOrgAccountSelectionFlowMock: vi.fn(),
    handleTreeSelectionChangeMock: vi.fn(),
  }));

vi.mock("./hooks/use-org-account-selection-flow", () => ({
  useOrgAccountSelectionFlow: useOrgAccountSelectionFlowMock,
}));

describe("OrgAccountSelection", () => {
  let baseFlowState: Record<string, unknown>;

  beforeEach(() => {
    useOrgAccountSelectionFlowMock.mockReset();
    handleTreeSelectionChangeMock.mockReset();

    const accountLookup = new Map([
      [
        "222222222222",
        {
          id: "222222222222",
          name: "Account Two",
          arn: "arn:aws:organizations::222222222222:account/o-123/222222222222",
          email: "two@example.com",
          status: "ACTIVE",
          joined_method: "CREATED",
          joined_timestamp: "2024-01-01T00:00:00Z",
          parent_id: "r-root",
          registration: {
            provider_exists: false,
            provider_id: null,
            organization_relation: "link_required",
            organizational_unit_relation: "not_applicable",
            provider_secret_state: "will_create",
            apply_status: APPLY_STATUS.READY,
            blocked_reasons: [],
          },
        },
      ],
    ]);

    baseFlowState = {
      accountAliases: {},
      accountLookup,
      applyError: null,
      canAdvanceToLaunch: false,
      discoveryResult: {
        roots: [],
        organizational_units: [],
        accounts: [],
      },
      handleTreeSelectionChange: handleTreeSelectionChangeMock,
      hasConnectionErrors: true,
      isTesting: false,
      isTestingView: true,
      isSelectionLocked: false,
      organizationExternalId: "o-abc123def4",
      selectedCount: 1,
      selectedIdsForTree: [],
      setAccountAlias: vi.fn(),
      showHeaderHelperText: true,
      totalAccounts: 2,
      treeDataWithConnectionState: [
        {
          id: "222222222222",
          name: "222222222222 - Account Two",
        },
      ],
    };

    useOrgAccountSelectionFlowMock.mockReturnValue(baseFlowState);
  });

  it("allows changing account selection after finishing connection tests", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <OrgAccountSelection
        onBack={vi.fn()}
        onNext={vi.fn()}
        onSkip={vi.fn()}
        onFooterChange={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("checkbox"));

    // Then
    expect(handleTreeSelectionChangeMock).toHaveBeenCalledWith([
      "222222222222",
    ]);
  });

  it("locks account selection while apply or connection test is running", async () => {
    // Given
    const user = userEvent.setup();
    useOrgAccountSelectionFlowMock.mockReturnValue({
      ...baseFlowState,
      isSelectionLocked: true,
    });
    render(
      <OrgAccountSelection
        onBack={vi.fn()}
        onNext={vi.fn()}
        onSkip={vi.fn()}
        onFooterChange={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("checkbox"));

    // Then
    expect(handleTreeSelectionChangeMock).not.toHaveBeenCalled();
  });
});
