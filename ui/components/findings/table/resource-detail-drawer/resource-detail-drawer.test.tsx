import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { FindingResourceRow } from "@/types";

import { ResourceDetailDrawer } from "./resource-detail-drawer";

const { pathnameMock } = vi.hoisted(() => ({
  pathnameMock: vi.fn(() => "/findings"),
}));

vi.mock("next/navigation", () => ({
  usePathname: pathnameMock,
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

vi.mock("./resource-detail-drawer-content", () => ({
  ResourceDetailDrawerContent: () => <div>Finding details</div>,
}));

describe("ResourceDetailDrawer", () => {
  beforeEach(() => {
    pathnameMock.mockReturnValue("/findings");
  });

  it("should update focused finding context when drawer navigation changes", () => {
    // Given
    const firstFinding = findingResource("finding-1", "bucket-1");
    const secondFinding = findingResource("finding-2", "bucket-2");
    const { rerender } = renderDrawer(firstFinding);
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"findingId":"finding-1"',
    );

    // When
    rerender(drawer(secondFinding));

    // Then
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"findingId":"finding-2"',
    );
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"resourceUid":"bucket-2"',
    );
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"source":"focused"',
    );
  });

  it("should scope a finding opened from an Attack Paths node", () => {
    // Given
    pathnameMock.mockReturnValue("/attack-paths");

    // When
    renderDrawer(findingResource("finding-attack-path", "bucket-attack-path"));

    // Then
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"scopeKey":"attack-paths:/attack-paths"',
    );
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"findingId":"finding-attack-path"',
    );
  });
});

function renderDrawer(currentResource: FindingResourceRow) {
  return render(drawer(currentResource));
}

function drawer(currentResource: FindingResourceRow) {
  return (
    <ResourceDetailDrawer
      open
      onOpenChange={vi.fn()}
      isLoading={false}
      isNavigating={false}
      checkMeta={null}
      currentIndex={0}
      totalResources={2}
      currentResource={currentResource}
      currentFinding={null}
      otherFindings={[]}
      onNavigatePrev={vi.fn()}
      onNavigateNext={vi.fn()}
      onMuteComplete={vi.fn()}
    />
  );
}

function findingResource(
  findingId: string,
  resourceUid: string,
): FindingResourceRow {
  return {
    id: findingId,
    rowType: "resource",
    findingId,
    checkId: "aws_s3_bucket_public_access",
    providerType: "aws",
    providerAlias: "Production",
    providerUid: "123456789012",
    resourceName: resourceUid,
    resourceType: "AwsS3Bucket",
    resourceGroup: "storage",
    resourceUid,
    service: "s3",
    region: "eu-west-1",
    severity: "critical",
    status: "FAIL",
    isMuted: false,
    firstSeenAt: null,
    lastSeenAt: null,
  };
}
