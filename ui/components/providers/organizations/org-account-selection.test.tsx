import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { OrgAccountSelection } from "./org-account-selection";

const { useOrgAccountSelectionFlowMock, handleTreeSelectionChangeMock } =
  vi.hoisted(() => ({
    useOrgAccountSelectionFlowMock: vi.fn(),
    handleTreeSelectionChangeMock: vi.fn(),
  }));

vi.mock("./hooks/use-org-account-selection-flow", () => ({
  useOrgAccountSelectionFlow: useOrgAccountSelectionFlowMock,
}));

vi.mock("@/components/shadcn/tree-view", () => ({
  TreeView: ({
    onSelectionChange,
  }: {
    onSelectionChange?: (ids: string[]) => void;
  }) => (
    <button onClick={() => onSelectionChange?.(["222222222222"])}>
      trigger-tree-selection
    </button>
  ),
}));

describe("OrgAccountSelection", () => {
  beforeEach(() => {
    useOrgAccountSelectionFlowMock.mockReset();
    handleTreeSelectionChangeMock.mockReset();
    useOrgAccountSelectionFlowMock.mockReturnValue({
      accountAliases: {},
      accountLookup: {},
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
      selectedIdsForTree: ["111111111111"],
      setAccountAlias: vi.fn(),
      showHeaderHelperText: true,
      totalAccounts: 2,
      treeDataWithConnectionState: [],
    });
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
    await user.click(
      screen.getByRole("button", { name: "trigger-tree-selection" }),
    );

    // Then
    expect(handleTreeSelectionChangeMock).toHaveBeenCalledWith([
      "222222222222",
    ]);
  });
});
