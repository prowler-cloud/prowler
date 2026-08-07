import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import {
  LighthouseSkillsRowButton,
  LighthouseSkillsSubmenu,
} from "./lighthouse-skills-launch";

const { requestPanelSkillLaunchMock, requestPanelChatMessageMock } = vi.hoisted(
  () => ({
    requestPanelSkillLaunchMock: vi.fn(),
    requestPanelChatMessageMock: vi.fn(),
  }),
);

vi.mock("@/app/(prowler)/lighthouse/_lib/panel-chat-store", () => ({
  requestPanelSkillLaunch: requestPanelSkillLaunchMock,
  requestPanelChatMessage: requestPanelChatMessageMock,
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
  DropdownMenuLabel: ({ children }: { children?: ReactNode }) => (
    <div>{children}</div>
  ),
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

  it("should start a fresh conversation from the row prompt with its finding context", async () => {
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
    await user.type(
      screen.getByRole("textbox", { name: "Ask Lighthouse anything" }),
      "Is this exposed?{Enter}",
    );

    // Then
    expect(onSkillLaunch).toHaveBeenCalledOnce();
    expect(useSidePanelStore.getState()).toMatchObject({
      isOpen: true,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
    });
    await vi.waitFor(() =>
      expect(requestPanelChatMessageMock).toHaveBeenCalledWith(
        "Is this exposed?",
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

  it("should render the recommended lead and the prompt row in the submenu", () => {
    // Given / When
    render(
      <LighthouseSkillsSubmenu onLaunch={vi.fn()} onSubmitPrompt={vi.fn()} />,
    );

    // Then — same shared menu body everywhere: Recommended group + footer.
    expect(screen.getByText("Recommended")).toBeInTheDocument();
    expect(
      screen.getByRole("textbox", { name: "Ask Lighthouse anything" }),
    ).toBeInTheDocument();
  });
});
