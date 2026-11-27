import { describe, expect, it, vi } from "vitest";

import { render } from "@/__tests__/render-browser";

import { AiCompliance } from "./_components/ai-compliance";
import { AiStack } from "./_components/ai-stack";
import { TopRisks } from "./_components/top-risks";
import type { AiStackLayer } from "./_types";

// Only OpenAI is installed from the Registry.
vi.mock(
  "@/components/providers/workflow/forms/use-registry-provider-discovery",
  () => ({
    useRegistryProviderDiscovery: () => ({
      result: {
        status: "ready",
        options: [{ type: "openai", label: "OpenAI" }],
      },
    }),
  }),
);

vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ permissions: { manage_providers: true } }),
}));

const NONE = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };

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
          newFail: 0,
          severity: { ...NONE, high: 1 },
          services: ["apikey"],
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
          newFail: 0,
          severity: { ...NONE, critical: 1, medium: 3 },
          services: ["bedrock", "sagemaker"],
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
          newFail: 0,
          severity: NONE,
          services: [],
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
          newFail: 0,
          severity: NONE,
          services: [],
        },
      ],
    },
  ];

  it("opens a provider's failed AI findings, and lists the services that fail", async () => {
    const screen = await render(
      <AiStack
        layers={layers}
        filters={{ "filter[provider_type__in]": "openai,aws" }}
      />,
    );
    const row = screen.getByRole("link", { name: /AWS/ });

    await expect
      .element(row)
      .toHaveAttribute(
        "href",
        "/findings?filter%5Bcategory__in%5D=gen-ai&filter%5Bstatus__in%5D=FAIL&filter%5Bmuted%5D=false&filter%5Bprovider_type__in%5D=aws",
      );
    await expect.element(row.getByText("sagemaker")).toBeVisible();
    await expect.element(row.getByTitle("1 critical")).toBeVisible();
  });

  it("tells a cloud without a completed scan from one without AI services", async () => {
    const screen = await render(<AiStack layers={layers} filters={{}} />);

    await expect
      .element(screen.getByText("No completed scan yet"))
      .toBeVisible();
    await expect
      .element(screen.getByRole("link", { name: "Launch scan" }))
      .toHaveAttribute("href", "/scans");
    await expect
      .element(screen.getByText("No AI services found"))
      .toBeVisible();
    // Neither has results to open.
    await expect
      .element(screen.getByRole("link", { name: /Azure|GCP/ }))
      .not.toBeInTheDocument();
  });

  it("sends a model vendor that is not installed to the Registry instead of Add Provider", async () => {
    const notConnected = {
      scope: "0 accounts",
      connected: false,
      scanned: false,
      pass: 0,
      fail: 0,
      manual: 0,
      newFail: 0,
      severity: NONE,
      services: [],
    };
    const screen = await render(
      <AiStack
        layers={[
          {
            id: "model-vendors",
            name: "Model vendors",
            description: "",
            providers: [
              { type: "claude", name: "Claude", ...notConnected },
              { type: "openai", name: "OpenAI", ...notConnected },
            ],
          },
        ]}
        filters={{}}
      />,
    );

    await expect
      .element(screen.getByRole("link", { name: "Install from Registry" }))
      .toHaveAttribute("href", "/registry?filter%5Bsearch%5D=Claude");
    // OpenAI is installed, so the wizard can connect it.
    await expect
      .element(screen.getByRole("button", { name: "Add Provider" }))
      .toBeVisible();
  });

  it("points to the Registry when no AI framework is installed", async () => {
    const screen = await render(<AiCompliance frameworks={[]} />);

    await expect
      .element(screen.getByText("No AI frameworks installed"))
      .toBeVisible();
    await expect
      .element(screen.getByRole("link", { name: "Install from Registry" }))
      .toHaveAttribute("href", "/registry?filter%5Bcapability%5D=compliance");
  });

  it("keeps a long check title inside its row on a narrow screen", async () => {
    const screen = await render(
      <div data-responsive-container className="@container w-[480px]">
        <TopRisks
          filters={{}}
          risks={[
            {
              checkId: "bedrock_guardrails_configured",
              title:
                "Amazon Bedrock guardrails are configured with sensitive information filters for every model invocation",
              severity: "high",
              providerName: "AWS",
              affected: "12 resources",
            },
          ]}
        />
      </div>,
    );

    const title = screen.getByRole("link", { name: /guardrails/ }).element();
    expect(title.getBoundingClientRect().right).toBeLessThanOrEqual(
      title.closest("li")!.getBoundingClientRect().right,
    );
  });
});
