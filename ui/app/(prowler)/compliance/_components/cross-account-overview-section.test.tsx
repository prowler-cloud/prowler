import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getCompliancesOverview } from "@/actions/compliances";
import { getAllProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";

import { CrossAccountOverviewSection } from "./cross-account-overview-section";

vi.mock("@/actions/providers", () => ({
  getAllProviders: vi.fn(),
}));

vi.mock("@/actions/scans", () => ({
  getScans: vi.fn(),
}));

vi.mock("@/actions/compliances", () => ({
  getCompliancesOverview: vi.fn(),
}));

vi.mock("@/components/icons/providers-badge/provider-type-icon", () => ({
  ProviderTypeIcon: () => <span aria-hidden="true" />,
}));

vi.mock("./cross-account-framework-card", () => ({
  CrossAccountFrameworkCard: ({
    complianceId,
    providerType,
  }: {
    complianceId: string;
    providerType: string;
  }) => (
    <div data-testid="cross-account-card">
      {providerType}:{complianceId}
    </div>
  ),
}));

// Only the fields the section reads; the full ProviderProps shape is not
// needed for these tests.
type ProvidersResponse = Awaited<ReturnType<typeof getAllProviders>>;
const providersResponse = (
  providers: Array<{ id: string; type: string }>,
): ProvidersResponse =>
  ({
    data: providers.map(({ id, type }) => ({
      id,
      attributes: { provider: type, uid: `uid-${id}`, alias: null },
    })),
  }) as unknown as ProvidersResponse;

const scansFor = (scans: Array<{ id: string; providerId: string }>) => ({
  data: scans.map(({ id, providerId }) => ({
    id,
    relationships: { provider: { data: { id: providerId } } },
  })),
  included: [
    { type: "providers", id: "aws-1", attributes: { provider: "aws" } },
    { type: "providers", id: "aws-2", attributes: { provider: "aws" } },
    { type: "providers", id: "gcp-1", attributes: { provider: "gcp" } },
  ],
});

const renderSection = async (
  searchParams: Record<string, string | string[] | undefined> = {},
) => render(await CrossAccountOverviewSection({ searchParams }));

describe("CrossAccountOverviewSection", () => {
  beforeEach(() => {
    vi.mocked(getAllProviders).mockReset();
    vi.mocked(getScans).mockReset();
    vi.mocked(getCompliancesOverview).mockReset();
  });

  it("renders nothing when no provider type has two or more accounts", async () => {
    // Given: one AWS and one GCP account — no multi-account type.
    vi.mocked(getAllProviders).mockResolvedValue(
      providersResponse([
        { id: "aws-1", type: "aws" },
        { id: "gcp-1", type: "gcp" },
      ]),
    );
    vi.mocked(getScans).mockResolvedValue(scansFor([]));

    // When
    const { container } = await renderSection();

    // Then: single-account tenants keep the tab unchanged.
    expect(container).toBeEmptyDOMElement();
    expect(getCompliancesOverview).not.toHaveBeenCalled();
  });

  it("lists the eligible type's frameworks, excluding universal and ThreatScore", async () => {
    // Given: two AWS accounts (eligible) and one GCP account (not).
    vi.mocked(getAllProviders).mockResolvedValue(
      providersResponse([
        { id: "aws-1", type: "aws" },
        { id: "aws-2", type: "aws" },
        { id: "gcp-1", type: "gcp" },
      ]),
    );
    vi.mocked(getScans).mockResolvedValue(
      scansFor([{ id: "scan-1", providerId: "aws-1" }]),
    );
    vi.mocked(getCompliancesOverview).mockResolvedValue({
      data: [
        {
          id: "cis_2.0_aws",
          attributes: { framework: "CIS", version: "2.0" },
        },
        // Universal frameworks have their own cross-provider cards above.
        {
          id: "csa_ccm_4.0",
          attributes: { framework: "CSA-CCM", version: "4.0" },
        },
        // ThreatScore is excluded, matching the per-scan grid.
        {
          id: "prowler_threatscore_aws",
          attributes: { framework: "ProwlerThreatScore", version: "1.0" },
        },
      ],
    });

    // When
    await renderSection();

    // Then: one collapsed group per eligible type, counts on the header,
    // cards revealed only on expand.
    expect(screen.getByText("Across providers")).toBeInTheDocument();
    expect(screen.getByText("AWS")).toBeInTheDocument();
    expect(screen.getByText("1 framework · 2 providers")).toBeInTheDocument();
    expect(screen.queryByTestId("cross-account-card")).not.toBeInTheDocument();

    await userEvent
      .setup()
      .click(screen.getByRole("button", { name: "Item aws" }));

    const cards = screen.getAllByTestId("cross-account-card");
    expect(cards).toHaveLength(1);
    expect(cards[0]).toHaveTextContent("aws:cis_2.0_aws");
    expect(getCompliancesOverview).toHaveBeenCalledWith({ scanId: "scan-1" });
  });

  it("respects the tab's provider type filter", async () => {
    // Given: AWS is eligible but filtered out.
    vi.mocked(getAllProviders).mockResolvedValue(
      providersResponse([
        { id: "aws-1", type: "aws" },
        { id: "aws-2", type: "aws" },
      ]),
    );
    vi.mocked(getScans).mockResolvedValue(
      scansFor([{ id: "scan-1", providerId: "aws-1" }]),
    );

    // When
    const { container } = await renderSection({
      "filter[provider_type__in]": "gcp",
    });

    // Then
    expect(container).toBeEmptyDOMElement();
    expect(getCompliancesOverview).not.toHaveBeenCalled();
  });

  it("scopes provider counts to the active account and group filters", async () => {
    // Given: three AWS providers exist, but only two match the active filters.
    vi.mocked(getAllProviders).mockImplementation(async ({ filters } = {}) => {
      const isFiltered =
        filters?.["filter[id__in]"] === "aws-1,aws-2" &&
        filters?.["filter[provider_groups__in]"] === "group-1";

      return providersResponse(
        isFiltered
          ? [
              { id: "aws-1", type: "aws" },
              { id: "aws-2", type: "aws" },
            ]
          : [
              { id: "aws-1", type: "aws" },
              { id: "aws-2", type: "aws" },
              { id: "aws-3", type: "aws" },
            ],
      );
    });
    vi.mocked(getScans).mockResolvedValue(
      scansFor([{ id: "scan-1", providerId: "aws-1" }]),
    );
    vi.mocked(getCompliancesOverview).mockResolvedValue({
      data: [
        {
          id: "cis_2.0_aws",
          attributes: { framework: "CIS", version: "2.0" },
        },
      ],
    });

    // When
    await renderSection({
      "filter[provider_id__in]": "aws-1,aws-2",
      "filter[provider_groups__in]": "group-1",
    });

    // Then: the overview count matches the same provider set as the detail.
    expect(screen.getByText("1 framework · 2 providers")).toBeInTheDocument();
    expect(screen.queryByText(/3 providers/)).not.toBeInTheDocument();
  });

  it("loads one representative completed scan for every eligible provider type", async () => {
    // Given: two eligible types whose representative scans must be resolved
    // independently, regardless of how many other scans the tenant has.
    vi.mocked(getAllProviders).mockResolvedValue(
      providersResponse([
        { id: "aws-1", type: "aws" },
        { id: "aws-2", type: "aws" },
        { id: "gcp-1", type: "gcp" },
        { id: "gcp-2", type: "gcp" },
      ]),
    );
    vi.mocked(getScans).mockImplementation(async ({ filters }) => {
      const providerType = (
        filters as Record<string, string | undefined> | undefined
      )?.["filter[provider_type]"];
      if (providerType === "aws") {
        return scansFor([{ id: "scan-aws", providerId: "aws-1" }]);
      }
      if (providerType === "gcp") {
        return scansFor([{ id: "scan-gcp", providerId: "gcp-1" }]);
      }
      return scansFor([]);
    });
    vi.mocked(getCompliancesOverview).mockResolvedValue({
      data: [
        {
          id: "framework-1",
          attributes: { framework: "Framework", version: "1.0" },
        },
      ],
    });

    // When
    await renderSection();

    // Then
    expect(screen.getByText("AWS")).toBeInTheDocument();
    expect(screen.getByText("Google Cloud")).toBeInTheDocument();
    expect(getScans).toHaveBeenCalledTimes(2);
    expect(getCompliancesOverview).toHaveBeenCalledWith({
      scanId: "scan-aws",
    });
    expect(getCompliancesOverview).toHaveBeenCalledWith({
      scanId: "scan-gcp",
    });
  });
});
