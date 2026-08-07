import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import {
  LighthouseSkillsRowButton,
  LighthouseSkillsSubmenu,
} from "./lighthouse-skills-launch";

const { requestPanelSkillLaunchMock } = vi.hoisted(() => ({
  requestPanelSkillLaunchMock: vi.fn(),
}));

vi.mock("@/app/(prowler)/lighthouse/_lib/panel-chat-store", () => ({
  requestPanelSkillLaunch: requestPanelSkillLaunchMock,
}));

vi.mock("@/components/shadcn/dropdown", () => ({
  ActionDropdown: ({
    children,
    trigger,
  }: {
    children: ReactNode;
    trigger?: ReactNode;
  }) => (
    <div>
      {trigger}
      {children}
    </div>
  ),
  ActionDropdownItem: ({
    label,
    onSelect,
  }: {
    label: string;
    onSelect: () => void;
  }) => <button onClick={onSelect}>{label}</button>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuSub: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuSubContent: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  DropdownMenuSubTrigger: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
}));

describe("Lighthouse skills launch controls", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useSidePanelStore.setState({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
    });
  });

  it("should render the shared submenu and launch the selected skill", async () => {
    // Given
    const user = userEvent.setup();
    const onLaunch = vi.fn();
    render(<LighthouseSkillsSubmenu onLaunch={onLaunch} />);

    // When
    await user.click(screen.getByRole("button", { name: "Triage Decision" }));

    // Then
    expect(screen.getByText("Lighthouse Skills")).toBeInTheDocument();
    expect(onLaunch).toHaveBeenCalledWith(
      expect.objectContaining({ id: "triage-decision" }),
    );
  });

  it("should open chat and launch a row skill with its finding context", async () => {
    // Given
    const user = userEvent.setup();
    const onSkillLaunch = vi.fn();
    render(
      <LighthouseSkillsRowButton
        findingItem={{
          kind: "finding",
          id: "finding-1",
          source: "focused",
          scopeKey: "findings:/findings",
          label: "Finding finding-1",
          findingId: "finding-1",
        }}
        onSkillLaunch={onSkillLaunch}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Triage Decision" }));

    // Then
    expect(onSkillLaunch).toHaveBeenCalledOnce();
    expect(useSidePanelStore.getState()).toMatchObject({
      isOpen: true,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
    });
    await vi.waitFor(() =>
      expect(requestPanelSkillLaunchMock).toHaveBeenCalledWith(
        expect.objectContaining({ id: "triage-decision" }),
        {
          schemaVersion: 1,
          transport: "inline",
          items: [
            expect.objectContaining({
              kind: "finding",
              findingId: "finding-1",
            }),
          ],
        },
      ),
    );
  });
});
