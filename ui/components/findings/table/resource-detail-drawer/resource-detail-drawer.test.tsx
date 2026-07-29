import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ResourceDrawerFinding } from "@/actions/findings";
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

  it("should ignore stale finding details while drawer navigation is in progress", () => {
    // Given
    const currentResource = findingResource("finding-new", "bucket-new");
    const staleFinding = drawerFinding({
      id: "finding-stale",
      resourceUid: "bucket-stale",
    });

    // When
    renderDrawer(currentResource, staleFinding, true);

    // Then
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"findingId":"finding-new"',
    );
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"resourceUid":"bucket-new"',
    );
  });

  it("should prefer loaded finding details when navigation completes", () => {
    // Given
    const currentResource = findingResource("finding-row", "bucket-row");
    const loadedFinding = drawerFinding({
      id: "finding-loaded",
      resourceUid: "bucket-loaded",
    });

    // When
    renderDrawer(currentResource, loadedFinding);

    // Then
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"findingId":"finding-loaded"',
    );
    expect(screen.getByTestId("focused-context")).toHaveTextContent(
      '"resourceUid":"bucket-loaded"',
    );
  });
});

function renderDrawer(
  currentResource: FindingResourceRow,
  currentFinding: ResourceDrawerFinding | null = null,
  isNavigating = false,
) {
  return render(drawer(currentResource, currentFinding, isNavigating));
}

function drawer(
  currentResource: FindingResourceRow,
  currentFinding: ResourceDrawerFinding | null = null,
  isNavigating = false,
) {
  return (
    <ResourceDetailDrawer
      open
      onOpenChange={vi.fn()}
      isLoading={false}
      isNavigating={isNavigating}
      checkMeta={null}
      currentIndex={0}
      totalResources={2}
      currentResource={currentResource}
      currentFinding={currentFinding}
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

function drawerFinding(
  overrides: Partial<ResourceDrawerFinding> = {},
): ResourceDrawerFinding {
  return {
    id: "finding-1",
    uid: "uid-1",
    checkId: "aws_s3_bucket_public_access",
    checkTitle: "S3 bucket public access",
    status: "FAIL",
    severity: "critical",
    delta: null,
    isMuted: false,
    mutedReason: null,
    firstSeenAt: null,
    updatedAt: null,
    resourceId: "resource-1",
    resourceUid: "bucket-1",
    resourceName: "bucket-1",
    resourceService: "s3",
    resourceRegion: "eu-west-1",
    resourceType: "AwsS3Bucket",
    resourceGroup: "storage",
    resourceDetails: null,
    resourceMetadata: null,
    providerType: "aws",
    providerAlias: "Production",
    providerUid: "123456789012",
    risk: "high",
    description: "S3 bucket allows public access",
    statusExtended: "Bucket is public",
    complianceFrameworks: [],
    categories: [],
    remediation: {
      recommendation: { text: "Block public access", url: "" },
      code: { cli: "", other: "", nativeiac: "", terraform: "" },
    },
    additionalUrls: [],
    scan: null,
    ...overrides,
  };
}
