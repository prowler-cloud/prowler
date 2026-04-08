import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { FindingProps } from "@/types";

import { FindingDetail } from "./finding-detail";

// Mock next/navigation
const mockRefresh = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: mockRefresh }),
  usePathname: () => "/findings",
  useSearchParams: () => new URLSearchParams(),
}));

// Mock @/components/shadcn to avoid next-auth import chain
vi.mock("@/components/shadcn", () => {
  const Slot = ({ children }: { children: React.ReactNode }) => <>{children}</>;
  return {
    Button: ({
      children,
      ...props
    }: React.ButtonHTMLAttributes<HTMLButtonElement> & {
      variant?: string;
      size?: string;
    }) => <button {...props}>{children}</button>,
    Drawer: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    DrawerClose: ({ children }: { children: React.ReactNode }) => (
      <>{children}</>
    ),
    DrawerContent: ({ children }: { children: React.ReactNode }) => (
      <>{children}</>
    ),
    DrawerDescription: ({ children }: { children: React.ReactNode }) => (
      <>{children}</>
    ),
    DrawerHeader: ({ children }: { children: React.ReactNode }) => (
      <>{children}</>
    ),
    DrawerTitle: ({ children }: { children: React.ReactNode }) => (
      <>{children}</>
    ),
    DrawerTrigger: Slot,
    InfoField: ({
      children,
      label,
    }: {
      children: React.ReactNode;
      label: string;
      variant?: string;
    }) => (
      <div>
        <span>{label}</span>
        {children}
      </div>
    ),
    Tabs: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    TabsContent: ({ children }: { children: React.ReactNode }) => (
      <>{children}</>
    ),
    TabsList: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    TabsTrigger: ({ children }: { children: React.ReactNode }) => (
      <>{children}</>
    ),
    Tooltip: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    TooltipContent: ({ children }: { children: React.ReactNode }) => (
      <>{children}</>
    ),
    TooltipTrigger: Slot,
  };
});

vi.mock("@/components/ui/code-snippet/code-snippet", () => ({
  CodeSnippet: ({ value }: { value: string }) => <span>{value}</span>,
}));

vi.mock("@/components/ui/custom/custom-link", () => ({
  CustomLink: ({ children }: { children: React.ReactNode }) => (
    <span>{children}</span>
  ),
}));

vi.mock("@/components/ui/entities", () => ({
  EntityInfo: () => <div data-testid="entity-info" />,
}));

vi.mock("@/components/ui/entities/date-with-time", () => ({
  DateWithTime: ({ dateTime }: { dateTime: string }) => <span>{dateTime}</span>,
}));

vi.mock("@/components/ui/table/severity-badge", () => ({
  SeverityBadge: ({ severity }: { severity: string }) => (
    <span>{severity}</span>
  ),
}));

vi.mock("@/components/ui/table/status-finding-badge", () => ({
  FindingStatus: {},
  StatusFindingBadge: ({ status }: { status: string }) => <span>{status}</span>,
}));

vi.mock("@/lib/iac-utils", () => ({
  buildGitFileUrl: () => null,
  extractLineRangeFromUid: () => null,
}));

vi.mock("@/lib/utils", () => ({
  cn: (...args: string[]) => args.filter(Boolean).join(" "),
}));

// Mock child components that are not under test
vi.mock("../mute-findings-modal", () => ({
  MuteFindingsModal: ({
    isOpen,
    findingIds,
  }: {
    isOpen: boolean;
    findingIds: string[];
  }) =>
    isOpen ? (
      <div data-testid="mute-modal">Muting {findingIds.length} finding(s)</div>
    ) : null,
}));

vi.mock("../muted", () => ({
  Muted: ({ isMuted }: { isMuted: boolean }) =>
    isMuted ? <span data-testid="muted-badge">Muted</span> : null,
}));

vi.mock("./delta-indicator", () => ({
  DeltaIndicator: () => null,
}));

vi.mock("@/components/shared/events-timeline/events-timeline", () => ({
  EventsTimeline: () => <div data-testid="events-timeline" />,
}));

vi.mock("react-markdown", () => ({
  default: ({ children }: { children: string }) => <span>{children}</span>,
}));

const baseFinding: FindingProps = {
  type: "findings",
  id: "finding-123",
  attributes: {
    uid: "uid-123",
    delta: null,
    status: "FAIL",
    status_extended: "S3 bucket is publicly accessible",
    severity: "high",
    check_id: "s3_bucket_public_access",
    muted: false,
    check_metadata: {
      risk: "Public access risk",
      notes: "",
      checkid: "s3_bucket_public_access",
      provider: "aws",
      severity: "high",
      checktype: [],
      dependson: [],
      relatedto: [],
      categories: ["security"],
      checktitle: "S3 Bucket Public Access Check",
      compliance: null,
      relatedurl: "",
      description: "Checks if S3 buckets are publicly accessible",
      remediation: {
        code: { cli: "", other: "", nativeiac: "", terraform: "" },
        recommendation: { url: "", text: "" },
      },
      servicename: "s3",
      checkaliases: [],
      resourcetype: "AwsS3Bucket",
      subservicename: "",
      resourceidtemplate: "",
    },
    raw_result: null,
    inserted_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-02T00:00:00Z",
    first_seen_at: "2024-01-01T00:00:00Z",
  },
  relationships: {
    resources: { data: [{ type: "resources", id: "res-1" }] },
    scan: {
      data: { type: "scans", id: "scan-1" },
      attributes: {
        name: "Daily Scan",
        trigger: "scheduled",
        state: "completed",
        unique_resource_count: 50,
        progress: 100,
        scanner_args: { checks_to_execute: [] },
        duration: 120,
        started_at: "2024-01-01T00:00:00Z",
        inserted_at: "2024-01-01T00:00:00Z",
        completed_at: "2024-01-01T00:02:00Z",
        scheduled_at: null,
        next_scan_at: "2024-01-02T00:00:00Z",
      },
    },
    resource: {
      data: [{ type: "resources", id: "res-1" }],
      id: "res-1",
      attributes: {
        uid: "arn:aws:s3:::my-bucket",
        name: "my-bucket",
        region: "us-east-1",
        service: "s3",
        tags: {},
        type: "AwsS3Bucket",
        inserted_at: "2024-01-01T00:00:00Z",
        updated_at: "2024-01-01T00:00:00Z",
        details: null,
        partition: "aws",
      },
      relationships: {
        provider: { data: { type: "providers", id: "prov-1" } },
        findings: {
          meta: { count: 1 },
          data: [{ type: "findings", id: "finding-123" }],
        },
      },
      links: { self: "/resources/res-1" },
    },
    provider: {
      data: { type: "providers", id: "prov-1" },
      attributes: {
        provider: "aws",
        uid: "123456789012",
        alias: "my-account",
        connection: {
          connected: true,
          last_checked_at: "2024-01-01T00:00:00Z",
        },
        inserted_at: "2024-01-01T00:00:00Z",
        updated_at: "2024-01-01T00:00:00Z",
      },
      relationships: {
        secret: { data: { type: "provider-secrets", id: "secret-1" } },
      },
      links: { self: "/providers/prov-1" },
    },
  },
  links: { self: "/findings/finding-123" },
};

describe("FindingDetail", () => {
  it("shows the Mute button for non-muted findings", () => {
    render(<FindingDetail findingDetails={baseFinding} />);

    expect(screen.getByRole("button", { name: /mute/i })).toBeInTheDocument();
  });

  it("hides the Mute button for muted findings", () => {
    const mutedFinding: FindingProps = {
      ...baseFinding,
      attributes: { ...baseFinding.attributes, muted: true },
    };

    render(<FindingDetail findingDetails={mutedFinding} />);

    expect(screen.queryByRole("button", { name: /mute/i })).toBeNull();
  });

  it("opens the mute modal when clicking the Mute button", async () => {
    const user = userEvent.setup();

    render(<FindingDetail findingDetails={baseFinding} />);

    expect(screen.queryByTestId("mute-modal")).toBeNull();

    await user.click(screen.getByRole("button", { name: /mute/i }));

    expect(screen.getByTestId("mute-modal")).toBeInTheDocument();
  });

  it("does not render the mute modal for muted findings", () => {
    const mutedFinding: FindingProps = {
      ...baseFinding,
      attributes: { ...baseFinding.attributes, muted: true },
    };

    render(<FindingDetail findingDetails={mutedFinding} />);

    expect(screen.queryByTestId("mute-modal")).toBeNull();
  });

  it("shows the muted badge for muted findings", () => {
    const mutedFinding: FindingProps = {
      ...baseFinding,
      attributes: { ...baseFinding.attributes, muted: true },
    };

    render(<FindingDetail findingDetails={mutedFinding} />);

    expect(screen.getByTestId("muted-badge")).toBeInTheDocument();
  });
});
