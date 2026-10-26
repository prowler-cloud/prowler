import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ComponentProps } from "react";
import { beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";

import { GraphNode } from "@/types/attack-paths";
import { IssueAttributes } from "@/types/issues";

const { getFindings, navigateToFinding } = vi.hoisted(() => ({
  getFindings: vi.fn(),
  navigateToFinding: vi.fn(),
}));
vi.mock("@/actions/findings", () => ({ getFindings }));
vi.mock("@/hooks/use-finding-details", () => ({
  useFindingDetails: () => ({
    findingDetails: null,
    findingDetailLoading: false,
    resetFindingDetails: vi.fn(),
    navigateToFinding,
  }),
}));
vi.mock("@/components/findings/table", () => ({
  FindingDetailDrawer: () => null,
}));
vi.mock("@/components/attack-paths/graph/attack-path-graph", () => ({
  AttackPathGraph: ({
    data,
    onNodeClick,
  }: {
    data: { nodes: GraphNode[] };
    onNodeClick: (node: GraphNode) => void;
  }) => (
    <button
      onClick={() =>
        onNodeClick(
          data.nodes.find((node) => node.labels.includes("ProwlerFinding")) ?? {
            id: "finding",
            labels: ["ProwlerFinding"],
            properties: { check_id: "s3_public", resource_uid: "bucket" },
          },
        )
      }
    >
      Open finding
    </button>
  ),
}));

import { IssueGraph } from "./issue-graph";

const issue = { legs: {} } as IssueAttributes;

it("requires provider and scan identifiers together in the graph props", () => {
  type Props = ComponentProps<typeof IssueGraph>;
  type BaseProps = Pick<Props, "issue" | "resourceUids">;

  expectTypeOf<BaseProps>().toExtend<Props>();
  expectTypeOf<
    BaseProps & { providerId: string; scanId: string }
  >().toExtend<Props>();
  expectTypeOf<BaseProps & { providerId: string }>().not.toExtend<Props>();
  expectTypeOf<BaseProps & { scanId: string }>().not.toExtend<Props>();
});

describe("IssueGraph finding lookup", () => {
  beforeEach(() => {
    navigateToFinding.mockResolvedValue(undefined);
  });

  it("opens a folded finding by id without another lookup", async () => {
    // Given
    render(
      <IssueGraph
        issue={issue}
        resourceUids={["bucket"]}
        findings={[
          {
            id: "folded-finding",
            checkId: "ssh",
            checkTitle: "SSH exposed",
            severity: "critical",
            resourceUid: "bucket",
          },
        ]}
        providerId="provider-1"
        scanId="scan-1"
      />,
    );

    // When
    await userEvent.click(screen.getByRole("button", { name: "Open finding" }));

    // Then
    expect(navigateToFinding).toHaveBeenCalledWith("folded-finding");
    expect(getFindings).not.toHaveBeenCalled();
  });

  it("limits lookup to the issue provider and verifies the returned scan", async () => {
    getFindings.mockResolvedValue({
      data: [
        {
          id: "finding-1",
          relationships: { scan: { data: { id: "scan-1" } } },
        },
      ],
    });
    const user = userEvent.setup();
    render(
      <IssueGraph
        issue={issue}
        resourceUids={["bucket"]}
        providerId="provider-1"
        scanId="scan-1"
      />,
    );
    await user.click(screen.getByRole("button", { name: "Open finding" }));
    expect(getFindings).toHaveBeenCalledWith({
      pageSize: 1,
      filters: {
        "filter[provider_id]": "provider-1",
        "filter[scan]": "scan-1",
        "filter[check_id]": "s3_public",
        "filter[resource_uid]": "bucket",
        "filter[status]": "FAIL",
      },
    });
    expect(navigateToFinding).toHaveBeenCalledWith("finding-1");
  });

  it("rejects a finding from a newer scan", async () => {
    getFindings.mockResolvedValue({
      data: [
        {
          id: "new-finding",
          relationships: { scan: { data: { id: "new-scan" } } },
        },
      ],
    });
    render(
      <IssueGraph
        issue={issue}
        resourceUids={["bucket"]}
        providerId="provider-1"
        scanId="scan-1"
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Open finding" }));
    expect(navigateToFinding).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "no longer available for the issue's scan",
    );
  });

  it("reports failed requests and allows retry", async () => {
    getFindings
      .mockRejectedValueOnce(new Error("Offline"))
      .mockResolvedValueOnce({ data: [] });
    render(
      <IssueGraph
        issue={issue}
        resourceUids={["bucket"]}
        providerId="provider-1"
        scanId="scan-1"
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Open finding" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Could not load this finding",
    );
    await userEvent.click(screen.getByRole("button", { name: "Open finding" }));
    expect(getFindings).toHaveBeenCalledTimes(2);
  });

  it("shows loading feedback and ignores concurrent clicks", async () => {
    let resolve!: (value: { data: [] }) => void;
    getFindings.mockReturnValue(
      new Promise((done) => {
        resolve = done;
      }),
    );
    render(
      <IssueGraph
        issue={issue}
        resourceUids={["bucket"]}
        providerId="provider-1"
        scanId="scan-1"
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Open finding" }));
    expect(screen.getByRole("status")).toHaveTextContent(
      "Loading finding details",
    );
    await userEvent.click(screen.getByRole("button", { name: "Open finding" }));
    expect(getFindings).toHaveBeenCalledOnce();
    await act(async () => resolve({ data: [] }));
    await waitFor(() =>
      expect(screen.queryByRole("status")).not.toBeInTheDocument(),
    );
  });

  it("does not look up findings without a provider and scan", async () => {
    render(<IssueGraph issue={issue} resourceUids={["bucket"]} />);
    await userEvent.click(screen.getByRole("button", { name: "Open finding" }));
    expect(getFindings).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "no provider or scan reference",
    );
  });
});
