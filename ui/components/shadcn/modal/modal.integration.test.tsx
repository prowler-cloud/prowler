import { describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import { InfoField } from "@/components/shadcn/info-field/info-field";

import { Modal } from "./modal";

const SHA256 =
  "41eae539eea1f34c20de7c4932408a0a0b258fe9a17334316db052b85101b6a8";

describe("Modal", () => {
  it("keeps long unbreakable content inside the dialog", async () => {
    // Given
    const screen = await render(
      <Modal open onOpenChange={vi.fn()} title="Status statement" size="lg">
        <div className="flex flex-col gap-4">
          <div className="grid grid-cols-2 gap-3">
            <InfoField label="Date">2026-11-06</InfoField>
            <InfoField label="Mode">Monitor only</InfoField>
          </div>
          <InfoField label="SHA-256">
            <CodeSnippet value={SHA256} />
          </InfoField>
        </div>
      </Modal>,
    );

    // When
    const dialog = screen.getByRole("dialog").element();
    const content = [
      screen.getByText("Monitor only").element(),
      screen.getByText(SHA256).element(),
    ];

    // Then
    const padding = parseFloat(getComputedStyle(dialog).paddingRight);
    const contentRight = dialog.getBoundingClientRect().right - padding;
    for (const element of content) {
      expect(element.getBoundingClientRect().right).toBeLessThan(
        contentRight + 1,
      );
    }
  });

  it("wraps a multiline hash so all of it shows inside the dialog", async () => {
    // Given
    const screen = await render(
      <Modal open onOpenChange={vi.fn()} title="Status statement" size="sm">
        <InfoField label="SHA-256">
          <CodeSnippet value={SHA256} multiline />
        </InfoField>
      </Modal>,
    );

    // When
    const dialog = screen.getByRole("dialog").element();
    const hash = screen.getByText(SHA256).element();

    // Then
    const padding = parseFloat(getComputedStyle(dialog).paddingRight);
    const contentRight = dialog.getBoundingClientRect().right - padding;
    expect(hash.getBoundingClientRect().right).toBeLessThan(contentRight + 1);
    expect(hash.scrollWidth).toBeLessThanOrEqual(hash.clientWidth);
    expect(hash.getBoundingClientRect().height).toBeGreaterThan(
      parseFloat(getComputedStyle(hash).lineHeight) * 1.5,
    );
  });
});
