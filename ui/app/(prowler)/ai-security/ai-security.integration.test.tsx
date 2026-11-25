import { describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";

import { AiCompliance } from "./_components/ai-compliance";
import type { AiFramework } from "./_types";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/ai-security",
  useSearchParams: () => new URLSearchParams(),
}));

const framework = (
  id: string,
  shortName: string,
  section: string,
): AiFramework => ({
  id,
  shortName,
  name: shortName,
  version: "1",
  unit: "requirements",
  sections: [{ code: "", name: section, pass: 1, fail: 1, manual: 0 }],
});

describe("AI Security compliance frameworks", () => {
  it("shows the sections of the framework that is picked", async () => {
    const screen = await render(
      <AiCompliance
        frameworks={[
          framework("owasp_llm", "OWASP LLM Top 10", "Prompt injection"),
          framework("nist_ai_rmf", "NIST AI RMF", "Govern"),
        ]}
      />,
    );

    await expect
      .element(screen.getByText("Prompt injection"))
      .toBeInTheDocument();

    await screen.getByRole("button", { name: /NIST AI RMF/ }).click();

    await expect.element(screen.getByText("Govern")).toBeInTheDocument();
    await expect
      .element(screen.getByText("Prompt injection"))
      .not.toBeInTheDocument();
  });
});
