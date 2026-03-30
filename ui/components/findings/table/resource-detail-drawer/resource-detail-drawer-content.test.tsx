import { render } from "@testing-library/react";
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Hoist mocks for components that pull in next-auth transitively
// ---------------------------------------------------------------------------

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
  usePathname: () => "/findings",
  useSearchParams: () => new URLSearchParams(),
  redirect: vi.fn(),
}));

vi.mock("next/image", () => ({
  default: ({ alt }: { alt: string }) => <span role="img" aria-label={alt} />,
}));

vi.mock("next/link", () => ({
  default: ({ children, href }: { children: ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

// Mock the entire shadcn barrel to avoid auth import chain
vi.mock("@/components/shadcn", () => {
  const Passthrough = ({ children }: { children?: ReactNode }) => (
    <>{children}</>
  );
  return {
    Badge: ({
      children,
      className,
    }: {
      children: ReactNode;
      className?: string;
    }) => <span className={className}>{children}</span>,
    Button: ({
      children,
      ...props
    }: ButtonHTMLAttributes<HTMLButtonElement> & {
      variant?: string;
      size?: string;
      asChild?: boolean;
    }) => <button {...props}>{children}</button>,
    InfoField: ({
      children,
      label,
    }: {
      children: ReactNode;
      label: string;
      variant?: string;
    }) => (
      <div>
        <span>{label}</span>
        {children}
      </div>
    ),
    Tabs: Passthrough,
    TabsContent: ({
      children,
      value,
    }: {
      children: ReactNode;
      value: string;
    }) => <div data-value={value}>{children}</div>,
    TabsList: Passthrough,
    TabsTrigger: ({
      children,
      value,
    }: {
      children: ReactNode;
      value: string;
    }) => <button data-value={value}>{children}</button>,
    Tooltip: Passthrough,
    TooltipContent: Passthrough,
    TooltipTrigger: Passthrough,
  };
});

vi.mock("@/components/shadcn/card/card", () => ({
  Card: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

vi.mock("@/components/shadcn/dropdown", () => ({
  ActionDropdown: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  ActionDropdownItem: () => null,
}));

vi.mock("@/components/shadcn/skeleton/skeleton", () => ({
  Skeleton: () => <div />,
}));

vi.mock("@/components/shadcn/spinner/spinner", () => ({
  Spinner: () => <div data-testid="spinner" />,
}));

vi.mock("@/components/shadcn/tooltip", () => ({
  Tooltip: ({ children }: { children: ReactNode }) => <>{children}</>,
  TooltipContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  TooltipTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

vi.mock("@/components/findings/mute-findings-modal", () => ({
  MuteFindingsModal: () => null,
}));

vi.mock("@/components/findings/send-to-jira-modal", () => ({
  SendToJiraModal: () => null,
}));

vi.mock("@/components/findings/markdown-container", () => ({
  MarkdownContainer: ({ children }: { children: ReactNode }) => children,
}));

vi.mock("@/components/icons", () => ({
  getComplianceIcon: vi.fn(() => null),
}));

vi.mock("@/components/icons/services/IconServices", () => ({
  JiraIcon: () => null,
}));

vi.mock("@/components/ui/code-snippet/code-snippet", () => ({
  CodeSnippet: ({ value }: { value: string }) => <span>{value}</span>,
}));

vi.mock("@/components/ui/custom/custom-link", () => ({
  CustomLink: ({ children, href }: { children: ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock("@/components/ui/entities/date-with-time", () => ({
  DateWithTime: ({ dateTime }: { dateTime: string }) => <span>{dateTime}</span>,
}));

vi.mock("@/components/ui/entities/entity-info", () => ({
  EntityInfo: () => null,
}));

vi.mock("@/components/ui/table", () => ({
  Table: ({ children }: { children: ReactNode }) => <table>{children}</table>,
  TableBody: ({ children }: { children: ReactNode }) => (
    <tbody>{children}</tbody>
  ),
  TableCell: ({ children }: { children: ReactNode }) => <td>{children}</td>,
  TableHead: ({ children }: { children: ReactNode }) => <th>{children}</th>,
  TableHeader: ({ children }: { children: ReactNode }) => (
    <thead>{children}</thead>
  ),
  TableRow: ({ children, ...props }: HTMLAttributes<HTMLTableRowElement>) => (
    <tr {...props}>{children}</tr>
  ),
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

vi.mock("@/components/shared/events-timeline/events-timeline", () => ({
  EventsTimeline: () => null,
}));

vi.mock("@/lib/region-flags", () => ({
  getRegionFlag: vi.fn(() => "🇺🇸"),
}));

vi.mock("@/lib/date-utils", () => ({
  getFailingForLabel: vi.fn(() => "2 days"),
  formatDuration: vi.fn(() => "5m"),
}));

vi.mock("@/lib/utils", () => ({
  cn: (...args: (string | undefined | false | null)[]) =>
    args.filter(Boolean).join(" "),
}));

vi.mock("../delta-indicator", () => ({
  DeltaIndicator: () => null,
}));

vi.mock("../notification-indicator", () => ({
  NotificationIndicator: () => null,
}));

vi.mock("./resource-detail-skeleton", () => ({
  ResourceDetailSkeleton: () => <div data-testid="skeleton" />,
}));

vi.mock("../../muted", () => ({
  Muted: () => null,
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

import type { ResourceDrawerFinding } from "@/actions/findings";

import { ResourceDetailDrawerContent } from "./resource-detail-drawer-content";
import type { CheckMeta } from "./use-resource-detail-drawer";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const mockCheckMeta: CheckMeta = {
  checkId: "s3_check",
  checkTitle: "S3 Check",
  risk: "High",
  description: "S3 description",
  complianceFrameworks: ["CIS-1.4", "PCI-DSS"],
  categories: ["security"],
  remediation: {
    recommendation: { text: "Fix it", url: "https://example.com" },
    code: { cli: "", other: "", nativeiac: "", terraform: "" },
  },
  additionalUrls: [],
};

const mockFinding: ResourceDrawerFinding = {
  id: "finding-1",
  uid: "uid-1",
  checkId: "s3_check",
  checkTitle: "S3 Check",
  status: "FAIL",
  severity: "critical",
  delta: null,
  isMuted: false,
  mutedReason: null,
  firstSeenAt: null,
  updatedAt: null,
  resourceId: "res-1",
  resourceUid: "arn:aws:s3:::bucket",
  resourceName: "my-bucket",
  resourceService: "s3",
  resourceRegion: "us-east-1",
  resourceType: "Bucket",
  resourceGroup: "default",
  providerType: "aws",
  providerAlias: "prod",
  providerUid: "123456789",
  risk: "High",
  description: "Description",
  statusExtended: "Status extended",
  complianceFrameworks: [],
  categories: [],
  remediation: {
    recommendation: { text: "Fix", url: "" },
    code: { cli: "", other: "", nativeiac: "", terraform: "" },
  },
  additionalUrls: [],
  scan: null,
};

// ---------------------------------------------------------------------------
// Fix 4: Dark mode — no hardcoded color classes
// ---------------------------------------------------------------------------

describe("ResourceDetailDrawerContent — dark mode token classes", () => {
  it("should NOT use hardcoded bg-white class anywhere in the component", () => {
    // Given
    const { container } = render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={mockFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // When — collect class strings from HTML elements only (skip SVG)
    const allElements = container.querySelectorAll("[class]");
    const classStrings = Array.from(allElements)
      .map((el) => (typeof el.className === "string" ? el.className : ""))
      .filter(Boolean);
    const hasBgWhite = classStrings.some((c) => c.includes("bg-white"));

    // Then — no hardcoded bg-white
    expect(hasBgWhite).toBe(false);
  });

  it("should NOT use hardcoded border-gray-300 class anywhere in the component", () => {
    // Given
    const { container } = render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={mockFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // When
    const allElements = container.querySelectorAll("[class]");
    const classStrings = Array.from(allElements)
      .map((el) => (typeof el.className === "string" ? el.className : ""))
      .filter(Boolean);
    const hasBorderGray = classStrings.some((c) =>
      c.includes("border-gray-300"),
    );

    // Then
    expect(hasBorderGray).toBe(false);
  });

  it("should NOT use hardcoded text-slate-950 class anywhere", () => {
    // Given
    const { container } = render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={mockFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // When
    const allElements = container.querySelectorAll("[class]");
    const classStrings = Array.from(allElements)
      .map((el) => (typeof el.className === "string" ? el.className : ""))
      .filter(Boolean);
    const hasTextSlate = classStrings.some((c) => c.includes("text-slate-950"));

    // Then
    expect(hasTextSlate).toBe(false);
  });
});
