import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ProviderGroup } from "@/types/components";
import { ProviderProps } from "@/types/providers";

import { OverviewProviderContext } from "./overview-provider-context";

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: ({ item }: { item: unknown }) => (
    <output data-testid="provider-context">{JSON.stringify(item)}</output>
  ),
}));

const providers = [
  {
    id: "prov-1",
    attributes: { provider: "aws", uid: "111111111111", alias: "Production" },
  },
] as unknown as ProviderProps[];

describe("OverviewProviderContext", () => {
  it("publishes URL-filtered providers as Lighthouse context", () => {
    render(
      <OverviewProviderContext
        searchParams={{ "filter[provider_id__in]": "prov-1" }}
        providers={providers}
        groups={[] as ProviderGroup[]}
      />,
    );

    const context = screen.getByTestId("provider-context");
    expect(context).toHaveTextContent('"label":"Provider: Production"');
    expect(context).toHaveTextContent('"providerUid":"111111111111"');
  });
});
