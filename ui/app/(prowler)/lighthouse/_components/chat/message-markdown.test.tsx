import { render, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { MessageMarkdown } from "./message-markdown";

describe("MessageMarkdown", () => {
  describe("when streamed inline code is incomplete", () => {
    it("should not render a code block inside a paragraph", async () => {
      // Given
      const consoleError = vi
        .spyOn(console, "error")
        .mockImplementation(() => undefined);
      const incompleteMarkdown =
        "The AWS resource policy is **currently:** `public\nwhile checking";

      // When
      const { container } = render(
        <MessageMarkdown text={incompleteMarkdown} isStreaming />,
      );
      await waitFor(() =>
        expect(container.querySelector("pre")).not.toBeNull(),
      );

      // Then
      expect(consoleError).not.toHaveBeenCalled();
    });
  });

  describe("when markdown contains a regular paragraph", () => {
    it("should preserve paragraph semantics", async () => {
      // Given
      const markdown = "The **AWS** resource is private.";

      // When
      const { container } = render(<MessageMarkdown text={markdown} />);
      await waitFor(() => expect(container.querySelector("p")).not.toBeNull());

      // Then
      expect(container.querySelector("p")).toHaveTextContent(
        "The AWS resource is private.",
      );
    });
  });

  describe("when markdown contains a standalone image", () => {
    it("should not wrap the image block in a paragraph", async () => {
      // Given
      const consoleError = vi
        .spyOn(console, "error")
        .mockImplementation(() => undefined);
      const markdown =
        "![AWS architecture](https://example.com/architecture.png)";

      // When
      const { container } = render(<MessageMarkdown text={markdown} />);
      await waitFor(() =>
        expect(container.querySelector("img")).not.toBeNull(),
      );

      // Then
      expect(consoleError).not.toHaveBeenCalled();
    });
  });
});
