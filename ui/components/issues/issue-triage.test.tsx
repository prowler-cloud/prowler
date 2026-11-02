import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { USAGE_LIMIT_MESSAGE } from "@/lib/action-errors";
import { PRICING_URL } from "@/lib/external-urls";

import { IssueTriage } from "./issue-triage";

const {
  addIssueNoteMock,
  getIssueNotesMock,
  refreshMock,
  toastMock,
  updateIssueTriageMock,
} = vi.hoisted(() => ({
  addIssueNoteMock: vi.fn(),
  getIssueNotesMock: vi.fn(),
  refreshMock: vi.fn(),
  toastMock: vi.fn(),
  updateIssueTriageMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: refreshMock }),
}));

vi.mock("@/actions/issues", () => ({
  addIssueNote: addIssueNoteMock,
  getIssueNotes: getIssueNotesMock,
  updateIssueTriage: updateIssueTriageMock,
}));

vi.mock("@/components/shadcn/toast/use-toast", () => ({
  useToast: () => ({ toast: toastMock }),
}));

describe("IssueTriage", () => {
  beforeAll(() => {
    // Radix Select needs pointer capture and scrollIntoView, which jsdom lacks.
    for (const name of [
      "hasPointerCapture",
      "setPointerCapture",
      "releasePointerCapture",
      "scrollIntoView",
    ]) {
      Object.defineProperty(HTMLElement.prototype, name, {
        configurable: true,
        value: vi.fn(() => false),
      });
    }
  });

  beforeEach(() => {
    getIssueNotesMock.mockResolvedValue([
      {
        id: "note-1",
        body: "Public by design.",
        insertedAt: "2026-10-20T10:00:00Z",
        author: "Ana",
      },
    ]);
    updateIssueTriageMock.mockResolvedValue({ success: true });
    addIssueNoteMock.mockResolvedValue({ success: true });
  });

  it("lists the notes already on the issue, with their author", async () => {
    render(<IssueTriage id="issue-1" status="open" />);

    expect(await screen.findByText("Public by design.")).toBeInTheDocument();
    expect(screen.getByText("Ana")).toBeInTheDocument();
    expect(screen.getByText("Oct 20, 2026")).toBeInTheDocument();
  });

  it("saves a new status together with its note", async () => {
    // Given
    const user = userEvent.setup();
    render(<IssueTriage id="issue-1" status="open" />);
    expect(screen.getByRole("button", { name: "Save triage" })).toBeDisabled();

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "Risk Accepted" }));
    await user.type(
      screen.getByRole("textbox", { name: "Triage note" }),
      "  Static site.  ",
    );
    await user.click(screen.getByRole("button", { name: "Save triage" }));

    // Then
    expect(updateIssueTriageMock).toHaveBeenCalledWith("issue-1", {
      status: "risk_accepted",
      note: "Static site.",
    });
    expect(addIssueNoteMock).not.toHaveBeenCalled();
    expect(refreshMock).toHaveBeenCalled();
    expect(screen.getByRole("textbox", { name: "Triage note" })).toHaveValue(
      "",
    );
  });

  it("records a note alone without touching the status", async () => {
    const user = userEvent.setup();
    render(<IssueTriage id="issue-1" status="remediating" />);

    await user.type(
      screen.getByRole("textbox", { name: "Triage note" }),
      "Asked the owner.",
    );
    await user.click(screen.getByRole("button", { name: "Save triage" }));

    expect(addIssueNoteMock).toHaveBeenCalledWith(
      "issue-1",
      "Asked the owner.",
    );
    expect(updateIssueTriageMock).not.toHaveBeenCalled();
  });

  it("follows a status someone else set, so a note alone does not undo it", async () => {
    // Given
    const user = userEvent.setup();
    const { rerender } = render(<IssueTriage id="issue-1" status="open" />);

    // When - a refresh brings another user's decision
    rerender(<IssueTriage id="issue-1" status="remediating" />);
    await user.type(
      screen.getByRole("textbox", { name: "Triage note" }),
      "Asked the owner.",
    );
    await user.click(screen.getByRole("button", { name: "Save triage" }));

    // Then
    expect(
      screen.getByRole("combobox", { name: "Triage status" }),
    ).toHaveTextContent("Remediating");
    expect(addIssueNoteMock).toHaveBeenCalledWith(
      "issue-1",
      "Asked the owner.",
    );
    expect(updateIssueTriageMock).not.toHaveBeenCalled();
  });

  it("locks the note while it is being saved", async () => {
    // Given
    let finish: (value: { success: true }) => void = () => {};
    addIssueNoteMock.mockReturnValue(
      new Promise((resolve) => {
        finish = resolve;
      }),
    );
    const user = userEvent.setup();
    render(<IssueTriage id="issue-1" status="open" />);
    const textbox = screen.getByRole("textbox", { name: "Triage note" });

    // When
    await user.type(textbox, "Asked the owner.");
    await user.click(screen.getByRole("button", { name: "Save triage" }));

    // Then
    expect(textbox).toBeDisabled();
    finish({ success: true });
    await waitFor(() => expect(textbox).toBeEnabled());
  });

  it("keeps the note and says why when the save fails", async () => {
    // Given
    updateIssueTriageMock.mockResolvedValue({
      error: "You do not have permission to perform this action.",
    });
    const user = userEvent.setup();
    render(<IssueTriage id="issue-1" status="open" />);

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "False Positive" }));
    await user.type(screen.getByRole("textbox", { name: "Triage note" }), "x");
    await user.click(screen.getByRole("button", { name: "Save triage" }));

    // Then
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({
        variant: "destructive",
        description: "You do not have permission to perform this action.",
      }),
    );
    expect(refreshMock).not.toHaveBeenCalled();
    expect(screen.getByRole("textbox", { name: "Triage note" })).toHaveValue(
      "x",
    );
  });

  it("offers the plans when the usage limit refuses the save", async () => {
    // Given
    updateIssueTriageMock.mockResolvedValue({
      error: USAGE_LIMIT_MESSAGE,
      status: 402,
    });
    const user = userEvent.setup();
    render(<IssueTriage id="issue-1" status="open" />);

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));
    await user.click(screen.getByRole("option", { name: "False Positive" }));
    await user.click(screen.getByRole("button", { name: "Save triage" }));

    // Then
    await waitFor(() => expect(toastMock).toHaveBeenCalled());
    const toastOptions = toastMock.mock.calls[0][0];
    render(<>{toastOptions.action}</>);
    expect(screen.getByRole("link", { name: "View plans" })).toHaveAttribute(
      "href",
      PRICING_URL,
    );
  });

  it("says so when the notes cannot be loaded, and loads them on retry", async () => {
    const user = userEvent.setup();
    getIssueNotesMock.mockResolvedValueOnce(undefined);
    render(<IssueTriage id="issue-1" status="open" />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not load the notes for this issue.",
    );

    await user.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByText("Public by design.")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
