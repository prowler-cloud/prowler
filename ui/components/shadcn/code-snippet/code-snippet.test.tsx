import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { CodeSnippet } from "./code-snippet";

describe("CodeSnippet", () => {
  it("should display the value and copy it to the clipboard", async () => {
    // Given
    const user = userEvent.setup();
    render(<CodeSnippet value="prowler --version" />);
    expect(screen.getByText("prowler --version")).toBeInTheDocument();

    // When
    await user.click(screen.getByRole("button", { name: "Copy to clipboard" }));

    // Then
    await expect(navigator.clipboard.readText()).resolves.toBe(
      "prowler --version",
    );
  });

  it("should copy the raw value even when a formatter changes the displayed text", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <CodeSnippet
        value="arn:aws:iam::123456789012:role/prowler"
        formatter={(value) => value.slice(0, 10)}
      />,
    );
    expect(screen.getByText("arn:aws:ia")).toBeInTheDocument();

    // When
    await user.click(screen.getByRole("button", { name: "Copy to clipboard" }));

    // Then
    await expect(navigator.clipboard.readText()).resolves.toBe(
      "arn:aws:iam::123456789012:role/prowler",
    );
  });

  it("should render only the copy button when hideCode is set", async () => {
    // Given
    const user = userEvent.setup();
    render(<CodeSnippet value="secret-token" hideCode />);

    // Then the value is not displayed but copying still works
    expect(screen.queryByText("secret-token")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Copy to clipboard" }));
    await expect(navigator.clipboard.readText()).resolves.toBe("secret-token");
  });

  describe("copy feedback", () => {
    it("should show the check icon after copying and revert after two seconds", async () => {
      // Given
      const user = userEvent.setup();
      render(<CodeSnippet value="copied-value" />);
      const copyButton = screen.getByRole("button", {
        name: "Copy to clipboard",
      });
      expect(copyButton.querySelector(".lucide-copy")).not.toBeNull();

      // When
      await user.click(copyButton);

      // Then the confirmation icon replaces the copy icon
      await waitFor(() =>
        expect(copyButton.querySelector(".lucide-check")).not.toBeNull(),
      );
      expect(copyButton.querySelector(".lucide-copy")).toBeNull();

      // Then the copy icon is restored once the 2s reset timeout elapses
      await waitFor(
        () => expect(copyButton.querySelector(".lucide-copy")).not.toBeNull(),
        { timeout: 3000 },
      );
      expect(copyButton.querySelector(".lucide-check")).toBeNull();
    });
  });
});
