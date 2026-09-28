import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
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

vi.mock("next/navigation", () => ({
  usePathname: () => "/resources",
}));

vi.mock("@/components/side-panel/detail-side-panel", () => ({
  DetailSidePanel: ({
    context,
    children,
  }: {
    context?: unknown;
    children: ReactNode;
  }) => (
    <>
      <output data-testid="focused-context">{JSON.stringify(context)}</output>
      {children}
    </>
  ),
}));

vi.mock("./resource-detail-content", () => ({
  ResourceDetailContent: () => <div>Resource details</div>,
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
  type: "resources",
  id: "resource-1",
  attributes: {
    inserted_at: "2026-07-22T10:00:00Z",
    updated_at: "2026-07-22T10:00:00Z",
    uid: "arn:aws:s3:::example",
    name: "example",
    service: "s3",
    region: "eu-west-1",
    type: "AwsS3Bucket",
    groups: ["storage"],
    failed_findings_count: 3,
    details: "full configuration must stay local",
    partition: "aws",
    tags: { owner: "security@example.com" },
    metadata: { secret: "do-not-send" },
  },
  relationships: {
    provider: {
      data: {
        type: "providers",
        id: "provider-1",
        attributes: {
          inserted_at: "2026-07-22T10:00:00Z",
          updated_at: "2026-07-22T10:00:00Z",
          provider: "aws",
          uid: "123456789012",
          alias: "Production",
          connection: {
            connected: true,
            last_checked_at: "2026-07-22T10:00:00Z",
          },
        },
        relationships: {
          secret: { data: { type: "provider-secrets", id: "secret-1" } },
        },
        links: { self: "/providers/provider-1" },
      },
    },
    findings: { meta: { count: 0 }, data: [] },
  },
  links: { self: "/resources/resource-1" },
} satisfies ResourceProps;

describe("ResourcesTableWithSelection", () => {
  it("publishes the loaded total and opens the selected resource detail", async () => {
    // Given
    const user = userEvent.setup();
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

    // When
    await user.click(screen.getByRole("button", { name: "Open resource" }));

    // Then
    expect(screen.getByText("Resource details")).toBeInTheDocument();
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"resourceId":"resource-1"',
    );
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"providerUid":"123456789012"',
    );
    expect(screen.getByTestId("focused-context")).not.toHaveTextContent(
      "full configuration must stay local",
    );
    expect(screen.getByTestId("focused-context")).not.toHaveTextContent(
      "security@example.com",
    );
    expect(screen.getByTestId("focused-context")).not.toHaveTextContent(
      "do-not-send",
    );
    expect(
      screen.queryByTestId("context-resource-resource-1"),
    ).not.toBeInTheDocument();
  });
});
