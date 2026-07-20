import { render, screen, within } from "@testing-library/react";
import { type ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { type MuteRuleTableData } from "./mute-rule-target-previews";

vi.mock("@/components/shadcn/modal", () => ({
  Modal: ({
    children,
    open,
    title,
  }: {
    children: ReactNode;
    open: boolean;
    title?: string;
  }) =>
    open ? (
      <div role="dialog" aria-label={title}>
        {children}
      </div>
    ) : null,
}));

import { MuteRuleTargetsModal } from "./mute-rule-targets-modal";

const longMuteRule: MuteRuleTableData = {
  type: "mute-rules",
  id: "mute-rule-1",
  attributes: {
    inserted_at: "2026-04-22T09:00:00Z",
    updated_at: "2026-04-22T09:05:00Z",
    name: "Finding triage: Risk Accepted - 019f1d6f-b304-78a6-8a59-9f648f65d123",
    reason: "Existing reason",
    enabled: true,
    finding_uids: ["uid-1"],
  },
  targetLabels: [
    "Security Hub is enabled with standards or integrations configured • hub/unknown",
  ],
  targetSummaryLabel:
    "Security Hub is enabled with standards or integrations configured • hub/unknown",
  hiddenTargetCount: 0,
};

describe("MuteRuleTargetsModal", () => {
  it("keeps long mute rule and finding cards constrained to the modal width", () => {
    // Given / When
    render(
      <MuteRuleTargetsModal
        muteRule={longMuteRule}
        open
        onOpenChange={vi.fn()}
      />,
    );

    // Then
    const dialog = screen.getByRole("dialog", { name: "Muted Findings" });
    const content = dialog.firstElementChild;
    if (!(content instanceof HTMLElement)) {
      throw new Error("Expected modal content wrapper");
    }

    const muteRuleCard = within(dialog)
      .getByText("Mute rule")
      .closest("div")?.parentElement;
    if (!(muteRuleCard instanceof HTMLElement)) {
      throw new Error("Expected mute rule card");
    }

    const targetList = within(dialog).getByRole("list");
    const targetsCard = targetList.parentElement;
    if (!(targetsCard instanceof HTMLElement)) {
      throw new Error("Expected targets card");
    }

    expect(content).toHaveClass("min-w-0", "max-w-full");
    expect(muteRuleCard).toHaveClass(
      "min-w-0",
      "max-w-full",
      "overflow-hidden",
    );
    expect(targetsCard).toHaveClass("min-w-0", "max-w-full", "overflow-hidden");
  });
});
