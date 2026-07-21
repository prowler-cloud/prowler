import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ResourceProps } from "@/types";

import { ResourcesTableWithSelection } from "./resources-table-with-selection";

vi.mock("@/components/shadcn/table", () => ({
  DataTable: ({
    data,
    onRowClick,
  }: {
    data: ResourceProps[];
    onRowClick: (row: { original: ResourceProps }) => void;
  }) => (
    <button type="button" onClick={() => onRowClick({ original: data[0] })}>
      Open resource
    </button>
  ),
}));

vi.mock("@/components/resources/resource-details-sheet", () => ({
  ResourceDetailsSheet: () => <div>Resource details</div>,
}));

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: ({
    contributorId,
    item,
  }: {
    contributorId: string;
    item: unknown;
  }) => (
    <output data-testid={`context-${contributorId}`}>
      {JSON.stringify(item)}
    </output>
  ),
}));

const resource = {
  id: "resource-1",
  attributes: {
    uid: "arn:aws:s3:::example",
    service: "s3",
    region: "eu-west-1",
    type: "AwsS3Bucket",
    failed_findings_count: 3,
  },
  relationships: {
    provider: { data: { attributes: { uid: "123456789012" } } },
  },
} as ResourceProps;

describe("ResourcesTableWithSelection", () => {
  it("publishes the loaded total and selected resource as context", async () => {
    render(
      <ResourcesTableWithSelection
        data={[resource]}
        metadata={{
          pagination: { page: 1, pages: 1, count: 17 },
          version: "v1",
        }}
      />,
    );

    expect(screen.getByTestId("context-resources-summary")).toHaveTextContent(
      '"total":17',
    );

    screen.getByRole("button", { name: "Open resource" }).click();

    expect(
      await screen.findByTestId("context-resource-resource-1"),
    ).toHaveTextContent('"providerUid":"123456789012"');
  });
});
