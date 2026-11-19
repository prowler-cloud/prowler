import { describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";

import { AiCompliance } from "./_components/ai-compliance";
import { getAiSecurityOverview } from "./_lib/mock-overview";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/ai-security",
  useSearchParams: () => new URLSearchParams(),
}));

describe("AI Security compliance frameworks", () => {
  it("shows the sections of the framework that is picked", async () => {
    const overview = await getAiSecurityOverview();
    const screen = await render(
      <AiCompliance frameworks={overview?.frameworks ?? []} />,
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
