import { describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";

import { AiCompliance } from "./_components/ai-compliance";
import { AiStack } from "./_components/ai-stack";
import type { AiStackLayer } from "./_types";

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

describe("AI Security compliance frameworks", () => {
  it("opens a framework card in its Compliance detail with the page's filters", async () => {
    navigation.search = "filter[provider_type__in]=openai";
    const screen = await render(
      <AiCompliance
        frameworks={[
          {
            complianceId: "owasp_llm_top_10_2025",
            title: "OWASP-LLM-Top-10",
            version: "2025",
            description: "",
            requirementsPassed: 4,
            requirementsFailed: 2,
            requirementsManual: 81,
            totalRequirements: 87,
            providerBreakdown: [],
          },
        ]}
      />,
    );

    await screen.getByRole("button", { name: /OWASP LLM Top 10/ }).click();
    expect(navigation.push).toHaveBeenLastCalledWith(
      "/compliance/OWASP-LLM-Top-10?mode=cross-provider&complianceId=owasp_llm_top_10_2025&version=2025&filter%5Bprovider_type__in%5D=openai",
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
          scanned: true,
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
          scanned: true,
          pass: 5,
          fail: 4,
          manual: 0,
        },
        {
          type: "azure",
          name: "Azure",
          scope: "1 account",
          connected: true,
          scanned: false,
          pass: 0,
          fail: 0,
          manual: 0,
        },
        {
          type: "gcp",
          name: "GCP",
          scope: "3 accounts",
          connected: true,
          scanned: true,
          pass: 0,
          fail: 0,
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

  it("tells a cloud without a completed scan from one without AI services", async () => {
    navigation.search = "";
    const screen = await render(<AiStack layers={layers} />);

    await expect
      .element(screen.getByText("No completed scan yet"))
      .toBeVisible();
    await expect
      .element(screen.getByRole("link", { name: "Launch scan" }))
      .toHaveAttribute("href", "/scans");
    await expect
      .element(screen.getByText("No AI services found"))
      .toBeVisible();
    // Neither has results to filter the page to.
    await expect
      .element(screen.getByRole("button", { name: /Azure|GCP/ }))
      .not.toBeInTheDocument();
  });
});
