import { describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";

import { AiCompliance } from "./_components/ai-compliance";
import { AiStack } from "./_components/ai-stack";
import type { AiFramework, AiStackLayer } from "./_types";

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

const framework: AiFramework = {
  id: "owasp_llm_top_10_2025",
  title: "OWASP-LLM-Top-10",
  shortName: "OWASP LLM Top 10",
  name: "OWASP Top 10 for LLM Applications",
  version: "2025",
  unit: "requirements",
  pass: 4,
  fail: 2,
  manual: 81,
};

describe("AI Security compliance frameworks", () => {
  it("opens a framework in Compliance across the model vendors in scope", async () => {
    const screen = await render(
      <AiCompliance
        frameworks={[framework]}
        filters={{
          "filter[provider_type__in]": "openai,aws",
          "filter[provider_groups__in]": "g1",
        }}
      />,
    );

    await expect
      .element(screen.getByRole("link", { name: /OWASP LLM Top 10/ }))
      .toHaveAttribute(
        "href",
        "/compliance/OWASP-LLM-Top-10?mode=cross-provider&complianceId=owasp_llm_top_10_2025&version=2025&filter%5Bprovider_type__in%5D=openai&filter%5Bprovider_groups__in%5D=g1",
      );
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
    {
      id: "cloud-ai-services",
      name: "Cloud AI services",
      description: "",
      providers: [
        {
          type: "aws",
          name: "AWS",
          scope: "2 accounts",
          connected: true,
          pass: 5,
          fail: 4,
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

  it("filters the page to a cloud's type and links to its gen-ai findings", async () => {
    navigation.search = "";
    const screen = await render(<AiStack layers={layers} />);

    await screen.getByRole("button", { name: /AWS/ }).click();
    expect(navigation.push).toHaveBeenLastCalledWith(
      "/ai-security?filter%5Bprovider_type__in%5D=aws",
      { scroll: false },
    );
    await expect
      .element(screen.getByRole("link", { name: /^AWS: 56%/ }))
      .toHaveAttribute(
        "href",
        expect.stringMatching(
          /filter%5Bcategory__in%5D=gen-ai.*filter%5Bprovider_type__in%5D=aws/,
        ),
      );
  });
});
