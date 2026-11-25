import { describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";

import { AiCompliance } from "./_components/ai-compliance";
import { AiStack } from "./_components/ai-stack";
import type { AiFramework, AiRequirement, AiStackLayer } from "./_types";

const navigation = vi.hoisted(() => ({
  push: vi.fn(),
  search: "",
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: navigation.push,
    replace: vi.fn(),
    refresh: vi.fn(),
  }),
  usePathname: () => "/ai-security",
  useSearchParams: () => new URLSearchParams(navigation.search),
}));

const getAiSectionRequirements = vi.hoisted(() =>
  vi.fn<() => Promise<AiRequirement[] | null>>(),
);
vi.mock("./_actions", () => ({ getAiSectionRequirements }));

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
  sections: [
    { id: section, code: "", name: section, pass: 1, fail: 1, manual: 0 },
  ],
});

describe("AI Security compliance frameworks", () => {
  it("shows the sections of the framework that is picked", async () => {
    const screen = await render(
      <AiCompliance
        frameworks={[
          framework("owasp_llm", "OWASP LLM Top 10", "Prompt injection"),
          framework("nist_ai_rmf", "NIST AI RMF", "Govern"),
        ]}
        filters={{}}
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

describe("AI Security requirement drill-down", () => {
  it("loads a section's requirements and checks when it is expanded", async () => {
    getAiSectionRequirements.mockResolvedValue([
      {
        id: "LLM02.3",
        name: "Enforce strict access controls",
        description: "",
        status: "FAIL",
        checks: [
          {
            id: "apikey_rotated_regularly",
            title: "API keys are rotated",
            status: "FAIL",
            failedResources: 3,
          },
        ],
      },
      {
        id: "LLM02.9",
        name: "Conceal system preamble",
        description: "Keep the system prompt private.",
        status: "MANUAL",
        checks: [],
      },
    ]);
    const screen = await render(
      <AiCompliance
        frameworks={[framework("owasp_llm", "OWASP LLM", "Disclosure")]}
        filters={{ "filter[provider_type__in]": "openai" }}
      />,
    );
    const section = screen.getByRole("button", { name: /Disclosure/ });

    expect(getAiSectionRequirements).not.toHaveBeenCalled();
    await expect.element(section).toHaveAttribute("aria-expanded", "false");

    await section.click();

    await expect.element(section).toHaveAttribute("aria-expanded", "true");
    await expect
      .element(screen.getByText("API keys are rotated"))
      .toBeInTheDocument();
    await expect
      .element(screen.getByRole("link", { name: "3 failed resources" }))
      .toHaveAttribute(
        "href",
        expect.stringContaining(
          "filter%5Bcheck_id__in%5D=apikey_rotated_regularly&filter%5Bprovider_type__in%5D=openai",
        ),
      );
    await expect
      .element(screen.getByText(/Needs a manual review/))
      .toHaveTextContent("Keep the system prompt private.");
  });
});

describe("AI Security stack", () => {
  const layers: AiStackLayer[] = [
    {
      id: "model-vendors",
      name: "Model vendors",
      description: "",
      providers: [
        {
          type: "openai",
          name: "OpenAI",
          scope: "1 account",
          connected: true,
          pass: 1,
          fail: 1,
          manual: 0,
        },
      ],
    },
  ];

  it("filters the page to a provider's type, and back to all when picked again", async () => {
    navigation.search = "";
    const screen = await render(<AiStack layers={layers} />);
    const row = screen.getByRole("button", { name: /OpenAI/ });

    await expect.element(row).toHaveAttribute("aria-pressed", "false");
    await row.click();
    expect(navigation.push).toHaveBeenLastCalledWith(
      "/ai-security?filter%5Bprovider_type__in%5D=openai",
      { scroll: false },
    );

    navigation.search = "filter[provider_type__in]=openai";
    screen.rerender(<AiStack layers={layers} />);

    await expect.element(row).toHaveAttribute("aria-pressed", "true");
    await row.click();
    expect(navigation.push).toHaveBeenLastCalledWith("/ai-security", {
      scroll: false,
    });
  });
});
