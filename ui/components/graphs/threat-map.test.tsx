import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ThreatMap } from "./threat-map";
import type { ThreatMapData } from "./threat-map.types";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("./horizontal-bar-chart", () => ({
  HorizontalBarChart: () => <div data-testid="bar-chart" />,
}));

function buildLocation(providerType: string, region: string) {
  return {
    id: `${providerType}-${region}`,
    name: `${providerType} - ${region}`,
    region,
    regionCode: region,
    providerType,
    coordinates: [-122.4, 37.8] as [number, number],
    totalFindings: 10,
    failFindings: 4,
    riskLevel: "high" as const,
    severityData: [
      { name: "Fail", value: 4, percentage: 40 },
      { name: "Pass", value: 6, percentage: 60 },
    ],
  };
}

describe("ThreatMap region selector", () => {
  it("auto-selects the region when it is the only one available", () => {
    const data: ThreatMapData = {
      locations: [
        buildLocation("okta", "global"),
        buildLocation("googleworkspace", "global"),
      ],
      regions: ["global"],
    };

    render(<ThreatMap data={data} />);

    const select = screen.getByRole("combobox", {
      name: "Filter threat map by region",
    });
    expect(select).toHaveValue("global");
    expect(screen.getByText("Global Regions")).toBeInTheDocument();
    expect(
      screen.queryByText("Select a location on the map to view details"),
    ).not.toBeInTheDocument();
  });

  it("keeps All Regions as default when there are multiple regions", () => {
    const data: ThreatMapData = {
      locations: [
        buildLocation("aws", "us-east-1"),
        buildLocation("okta", "global"),
      ],
      regions: ["global", "us-east-1"],
    };

    render(<ThreatMap data={data} />);

    const select = screen.getByRole("combobox", {
      name: "Filter threat map by region",
    });
    expect(select).toHaveValue("All Regions");
    expect(
      screen.getByRole("option", { name: "All Regions" }),
    ).toBeInTheDocument();
  });

  it("shows the global option capitalized while keeping its filter value", () => {
    const data: ThreatMapData = {
      locations: [
        buildLocation("aws", "us-east-1"),
        buildLocation("okta", "global"),
      ],
      regions: ["global", "us-east-1"],
    };

    render(<ThreatMap data={data} />);

    const globalOption = screen.getByRole("option", { name: "Global" });
    expect(globalOption).toHaveValue("global");
    expect(
      screen.getByRole("option", { name: "us-east-1" }),
    ).toBeInTheDocument();
  });
});
