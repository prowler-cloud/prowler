import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DecryptedText } from "./decrypted-text";

describe("DecryptedText", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "decrypted-text.tsx");
  const source = readFileSync(filePath, "utf8");

  it("delegates effects to local hooks instead of calling useEffect in the component", () => {
    expect(source).not.toContain("useEffect");
    expect(source).not.toContain("useEffect(");
  });

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
