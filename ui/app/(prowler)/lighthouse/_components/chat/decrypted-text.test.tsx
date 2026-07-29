import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DecryptedText } from "./decrypted-text";

describe("DecryptedText", () => {
  it("keeps the accessible text stable while the visible text is encrypted", async () => {
    // Given / When
    const { container } = render(
      <DecryptedText text="Secret Text" animateOn="click" characters="X" />,
    );

    // Then
    await waitFor(() =>
      expect(container.querySelector('[aria-hidden="true"]')).toHaveTextContent(
        "XXXXXX XXXX",
      ),
    );
    expect(
      screen.getByText("Secret Text", { selector: ".sr-only" }),
    ).toBeInTheDocument();
  });
});
