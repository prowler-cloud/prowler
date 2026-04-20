import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";
import { createPortal } from "react-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Hoist mocks for components that pull in next-auth transitively
// ---------------------------------------------------------------------------

const {
  mockGetComplianceIcon,
  mockGetCompliancesOverview,
  mockWindowOpen,
  mockClipboardWriteText,
  mockSearchParamsState,
  mockNotificationIndicator,
} = vi.hoisted(() => ({
  mockGetComplianceIcon: vi.fn((_: string) => null as string | null),
  mockGetCompliancesOverview: vi.fn(),
  mockWindowOpen: vi.fn(),
  mockClipboardWriteText: vi.fn(),
  mockSearchParamsState: { value: "" },
  mockNotificationIndicator: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
  usePathname: () => "/findings",
  useSearchParams: () => new URLSearchParams(mockSearchParamsState.value),
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
      variant: _variant,
      size: _size,
      asChild: _asChild,
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
  Card: ({ children, variant }: { children: ReactNode; variant?: string }) => (
    <div data-slot="card" data-variant={variant}>
      {children}
    </div>
  ),
}));

vi.mock("@/components/shadcn/dropdown", () => ({
  ActionDropdown: ({
    children,
    ariaLabel,
  }: {
    children: ReactNode;
    ariaLabel?: string;
  }) => (
    <div role="menu" aria-label={ariaLabel}>
      {children}
    </div>
  ),
  ActionDropdownItem: ({
    label,
    disabled,
    onSelect,
  }: {
    label: string;
    disabled?: boolean;
    onSelect?: () => void;
  }) => (
    <button type="button" disabled={disabled} onClick={onSelect}>
      {label}
    </button>
  ),
}));

vi.mock("@/components/shadcn/skeleton/skeleton", () => ({
  Skeleton: ({
    className,
    ...props
  }: HTMLAttributes<HTMLDivElement> & { className?: string }) => (
    <div data-testid="inline-skeleton" className={className} {...props} />
  ),
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
  MuteFindingsModal: ({
    isOpen,
    findingIds,
    onComplete,
  }: {
    isOpen: boolean;
    findingIds: string[];
    onComplete?: () => void;
  }) =>
    isOpen
      ? globalThis.document?.body &&
        // Render into body to mirror the real modal portal behavior.
        createPortal(
          <button type="button" onClick={onComplete}>
            {`Confirm mute ${findingIds.join(",")}`}
          </button>,
          globalThis.document.body,
        )
      : null,
}));

vi.mock("@/components/findings/send-to-jira-modal", () => ({
  SendToJiraModal: () => null,
}));

vi.mock("@/components/findings/markdown-container", () => ({
  MarkdownContainer: ({ children }: { children: ReactNode }) => children,
}));

vi.mock("@/components/shared/query-code-editor", () => ({
  QUERY_EDITOR_LANGUAGE: {
    OPEN_CYPHER: "openCypher",
    PLAIN_TEXT: "plainText",
    SHELL: "shell",
    HCL: "hcl",
    BICEP: "bicep",
    YAML: "yaml",
  },
  QueryCodeEditor: ({
    ariaLabel,
    language,
    value,
    copyValue,
  }: {
    ariaLabel: string;
    language?: string;
    value: string;
    copyValue?: string;
  }) => (
    <div
      data-testid="query-code-editor"
      data-aria-label={ariaLabel}
      data-language={language}
    >
      <span>{ariaLabel}</span>
      <span>{value}</span>
      <button
        type="button"
        onClick={() => mockClipboardWriteText(copyValue ?? value)}
      >
        Copy editor code
      </button>
    </div>
  ),
}));

vi.mock("@/actions/compliances", () => ({
  getCompliancesOverview: mockGetCompliancesOverview,
}));

vi.mock("@/components/icons", () => ({
  getComplianceIcon: mockGetComplianceIcon,
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
  NotificationIndicator: (props: Record<string, unknown>) => {
    mockNotificationIndicator(props);
    return null;
  },
  DeltaValues: { NEW: "new", CHANGED: "changed", NONE: "none" } as const,
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
import type { FindingResourceRow } from "@/types";

import { ResourceDetailDrawerContent } from "./resource-detail-drawer-content";
import type { CheckMeta } from "./use-resource-detail-drawer";

afterEach(() => {
  vi.clearAllMocks();
  mockSearchParamsState.value = "";
  mockGetComplianceIcon.mockImplementation(
    (_: string) => null as string | null,
  );
});

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

const mockResourceRow: FindingResourceRow = {
  id: "row-1",
  rowType: "resource",
  findingId: "finding-1",
  checkId: "s3_check",
  providerType: "aws",
  providerAlias: "prod",
  providerUid: "123456789",
  resourceName: "my-bucket",
  resourceType: "Bucket",
  resourceGroup: "default",
  resourceUid: "arn:aws:s3:::bucket",
  service: "s3",
  region: "us-east-1",
  severity: "critical",
  status: "FAIL",
  delta: null,
  isMuted: false,
  mutedReason: undefined,
  firstSeenAt: null,
  lastSeenAt: null,
};

// ---------------------------------------------------------------------------
// Fix 1: Lighthouse AI button text change
// ---------------------------------------------------------------------------

describe("ResourceDetailDrawerContent — Fix 1: Lighthouse AI button text", () => {
  it("should say 'Analyze this finding with Lighthouse AI' instead of 'View This Finding'", () => {
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

    // When — look for the lighthouse link
    const allText = container.textContent ?? "";

    // Then — correct text must be present, old text must be absent
    expect(allText.toLowerCase()).toContain("analyze this finding");
    expect(allText.toLowerCase()).not.toContain("view this finding");
  });
});

// ---------------------------------------------------------------------------
// Fix 2: Remediation heading labels — remove "Command" suffix
// ---------------------------------------------------------------------------

describe("ResourceDetailDrawerContent — Fix 2: Remediation heading labels", () => {
  const checkMetaWithCommands: CheckMeta = {
    ...mockCheckMeta,
    remediation: {
      recommendation: { text: "Fix it", url: "https://example.com" },
      code: {
        cli: "aws s3 ...",
        terraform: "resource aws_s3_bucket {}",
        nativeiac: "AWSTemplateFormatVersion: ...",
        other: "",
      },
    },
  };

  it("should render 'Terraform' heading without 'Command' suffix", () => {
    // Given
    const { container } = render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={checkMetaWithCommands}
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
    const allText = container.textContent ?? "";

    // Then — "Terraform" present, "Terraform Command" absent
    expect(allText).toContain("Terraform");
    expect(allText).not.toContain("Terraform Command");
  });

  it("should render 'CloudFormation' heading without 'Command' suffix", () => {
    // Given
    const { container } = render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={checkMetaWithCommands}
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
    const allText = container.textContent ?? "";

    // Then — "CloudFormation" present, "CloudFormation Command" absent
    expect(allText).toContain("CloudFormation");
    expect(allText).not.toContain("CloudFormation Command");
  });

  it("should still render 'CLI Command' label for CLI section", () => {
    // Given
    const { container } = render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={checkMetaWithCommands}
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
    const allText = container.textContent ?? "";

    // Then — CLI Command label must remain
    expect(allText).toContain("CLI Command");
  });

  it("should render remediation snippets with the shared code editor and copy CLI without the visual prompt", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={checkMetaWithCommands}
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
    const editors = screen.getAllByTestId("query-code-editor");
    await user.click(
      within(editors[0]).getByRole("button", { name: "Copy editor code" }),
    );

    // Then
    expect(editors).toHaveLength(3);
    expect(mockClipboardWriteText).toHaveBeenCalledWith("aws s3 ...");
    expect(screen.getByText("$ aws s3 ...")).toBeInTheDocument();
  });

  it("should pass syntax highlighting languages to each remediation editor", () => {
    // Given
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={checkMetaWithCommands}
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
    const editors = screen.getAllByTestId("query-code-editor");

    // Then
    expect(editors[0]).toHaveAttribute("data-language", "shell");
    expect(editors[1]).toHaveAttribute("data-language", "hcl");
    expect(editors[2]).toHaveAttribute("data-language", "yaml");
    expect(editors[0]).toHaveAttribute("data-aria-label", "CLI Command");
    expect(editors[2]).toHaveAttribute("data-aria-label", "CloudFormation");
  });
});

// ---------------------------------------------------------------------------
// Fix 5 & 6: Risk section has danger styling, sections have separators and bigger headings
// ---------------------------------------------------------------------------

describe("ResourceDetailDrawerContent — Fix 5 & 6: Risk section styling", () => {
  it("should wrap the Risk section in a Card component (data-slot='card')", () => {
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

    // When — find a Card with variant="danger" that contains the Risk label
    const dangerCards = Array.from(
      container.querySelectorAll('[data-variant="danger"]'),
    );
    const riskCard = dangerCards.find((el) =>
      el.textContent?.includes("Risk:"),
    );

    // Then — Risk section must be wrapped in a Card variant="danger"
    expect(riskCard).toBeDefined();
  });

  it("should use larger heading size for section labels (text-sm → text-base or larger)", () => {
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

    // When — look for section heading span with "Risk:"
    const headingSpans = Array.from(container.querySelectorAll("span")).filter(
      (el) => el.textContent?.trim() === "Risk:",
    );

    // Then — heading must not be tiny text-xs; should be text-sm or larger with font-semibold/font-medium
    expect(headingSpans.length).toBeGreaterThan(0);
    const riskHeading = headingSpans[0];
    expect(riskHeading.className).not.toContain("text-xs");
  });
});

// ---------------------------------------------------------------------------
// Fix 4: Compliance icon styling should match master
// ---------------------------------------------------------------------------

describe("ResourceDetailDrawerContent — compliance icon styling", () => {
  it("should render framework icons inside the same white chip used in master", () => {
    // Given
    mockGetComplianceIcon.mockImplementation((framework: string) =>
      framework === "CIS-1.4" ? "/cis.svg" : null,
    );

    render(
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
    const icon = screen.getByRole("img", { name: "CIS-1.4" });
    const chip = icon.closest("div");

    // Then
    expect(chip).toHaveClass("bg-white");
    expect(chip).toHaveClass("border-gray-300");
  });

  it("should render framework fallback pills with the same master styling", () => {
    // Given
    mockGetComplianceIcon.mockReturnValue(null);

    render(
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
    const chip = screen.getByText("PCI-DSS");

    // Then
    expect(chip).toHaveClass("bg-white");
    expect(chip).toHaveClass("border-gray-300");
  });
});

describe("ResourceDetailDrawerContent — compliance navigation", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("should resolve the clicked framework against the selected scan and navigate to compliance detail", async () => {
    // Given
    const user = userEvent.setup();
    vi.stubGlobal("open", mockWindowOpen);
    mockSearchParamsState.value =
      "filter[scan__in]=scan-selected&filter[region__in]=eu-west-1";
    mockGetCompliancesOverview.mockResolvedValue({
      data: [
        {
          id: "compliance-1",
          type: "compliance-overviews",
          attributes: {
            framework: "PCI-DSS",
            version: "4.0",
            requirements_passed: 10,
            requirements_failed: 2,
            requirements_manual: 0,
            total_requirements: 12,
          },
        },
      ],
    });

    render(
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
    await user.click(
      screen.getByRole("button", {
        name: "Open PCI-DSS compliance details",
      }),
    );

    // Then
    expect(mockGetCompliancesOverview).toHaveBeenCalledWith({
      scanId: "scan-selected",
    });
    expect(mockWindowOpen).toHaveBeenCalledWith(
      "/compliance/PCI-DSS?complianceId=compliance-1&version=4.0&scanId=scan-selected&filter%5Bregion__in%5D=eu-west-1",
      "_blank",
      "noopener,noreferrer",
    );
  });

  it("should use the current finding scan when no scan filter is active", async () => {
    // Given
    const user = userEvent.setup();
    vi.stubGlobal("open", mockWindowOpen);
    mockGetCompliancesOverview.mockResolvedValue({
      data: [
        {
          id: "compliance-2",
          type: "compliance-overviews",
          attributes: {
            framework: "PCI-DSS",
            version: "4.0",
            requirements_passed: 10,
            requirements_failed: 2,
            requirements_manual: 0,
            total_requirements: 12,
          },
        },
      ],
    });
    const findingWithScan = {
      ...mockFinding,
      scan: {
        id: "scan-from-finding",
        name: "Nightly scan",
        trigger: "manual",
        state: "completed",
        uniqueResourceCount: 25,
        progress: 100,
        duration: 300,
        startedAt: "2026-03-30T10:00:00Z",
        completedAt: "2026-03-30T10:05:00Z",
        insertedAt: "2026-03-30T09:59:00Z",
        scheduledAt: null,
      },
    };

    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={findingWithScan}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", {
        name: "Open PCI-DSS compliance details",
      }),
    );

    // Then
    expect(mockGetCompliancesOverview).toHaveBeenCalledWith({
      scanId: "scan-from-finding",
    });
    expect(mockWindowOpen).toHaveBeenCalledWith(
      "/compliance/PCI-DSS?complianceId=compliance-2&version=4.0&scanId=scan-from-finding",
      "_blank",
      "noopener,noreferrer",
    );
  });

  it("should navigate when the finding framework is a short alias of the compliance overview framework", async () => {
    // Given
    const user = userEvent.setup();
    vi.stubGlobal("open", mockWindowOpen);
    mockGetComplianceIcon.mockImplementation((framework: string) =>
      framework.toLowerCase().includes("kisa") ? "/kisa.svg" : null,
    );
    mockGetCompliancesOverview.mockResolvedValue({
      data: [
        {
          id: "compliance-kisa",
          type: "compliance-overviews",
          attributes: {
            framework: "KISA-ISMS-P",
            version: "1.0",
            requirements_passed: 5,
            requirements_failed: 1,
            requirements_manual: 0,
            total_requirements: 6,
          },
        },
      ],
    });
    const findingWithScan = {
      ...mockFinding,
      scan: {
        id: "scan-from-finding",
        name: "Nightly scan",
        trigger: "manual",
        state: "completed",
        uniqueResourceCount: 25,
        progress: 100,
        duration: 300,
        startedAt: "2026-03-30T10:00:00Z",
        completedAt: "2026-03-30T10:05:00Z",
        insertedAt: "2026-03-30T09:59:00Z",
        scheduledAt: null,
      },
    };

    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={{
          ...mockCheckMeta,
          complianceFrameworks: ["KISA"],
        }}
        currentIndex={0}
        totalResources={1}
        currentFinding={findingWithScan}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", {
        name: "Open KISA compliance details",
      }),
    );

    // Then
    expect(mockGetCompliancesOverview).toHaveBeenCalledWith({
      scanId: "scan-from-finding",
    });
    expect(mockWindowOpen).toHaveBeenCalledWith(
      "/compliance/KISA-ISMS-P?complianceId=compliance-kisa&version=1.0&scanId=scan-from-finding",
      "_blank",
      "noopener,noreferrer",
    );
  });
});

describe("ResourceDetailDrawerContent — other findings mute refresh", () => {
  it("should update only the muted other-finding row without refreshing the current finding group", async () => {
    // Given
    const user = userEvent.setup();
    const onMuteComplete = vi.fn();
    const otherFinding: ResourceDrawerFinding = {
      ...mockFinding,
      id: "finding-2",
      uid: "uid-2",
      checkId: "ec2_check",
      checkTitle: "EC2 Check",
      updatedAt: "2026-03-30T10:05:00Z",
    };

    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={mockFinding}
        otherFindings={[otherFinding]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={onMuteComplete}
      />,
    );

    // When
    const row = screen.getByText("EC2 Check").closest("tr");
    expect(row).not.toBeNull();

    await user.click(
      within(row as HTMLElement).getByRole("button", { name: "Mute" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Confirm mute finding-2" }),
    );

    // Then
    expect(
      within(row as HTMLElement).getByRole("button", { name: "Muted" }),
    ).toBeDisabled();
    expect(onMuteComplete).not.toHaveBeenCalled();
  });
});

describe("ResourceDetailDrawerContent — synthetic resource empty state", () => {
  it("should explain that simulated IaC resources never have other findings", () => {
    // Given/When
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={mockFinding}
        otherFindings={[]}
        showSyntheticResourceHint
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(
      screen.getByText(
        "No other findings are available for this IaC resource.",
      ),
    ).toBeInTheDocument();
  });
});

describe("ResourceDetailDrawerContent — current resource row display", () => {
  it("should render resource card fields from the current resource row instead of the fetched finding", () => {
    // Given
    const currentResource: FindingResourceRow = {
      ...mockResourceRow,
      providerAlias: "row-account",
      providerUid: "row-provider-uid",
      resourceName: "row-resource-name",
      resourceUid: "row-resource-uid",
      service: "row-service",
      region: "eu-west-1",
      resourceType: "row-type",
      resourceGroup: "row-group",
      severity: "low",
      status: "PASS",
    };
    const fetchedFinding: ResourceDrawerFinding = {
      ...mockFinding,
      providerAlias: "finding-account",
      providerUid: "finding-provider-uid",
      resourceName: "finding-resource-name",
      resourceUid: "finding-resource-uid",
      resourceService: "finding-service",
      resourceRegion: "ap-south-1",
      resourceType: "finding-type",
      resourceGroup: "finding-group",
      severity: "critical",
      status: "FAIL",
    };

    // When
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentResource={currentResource}
        currentFinding={fetchedFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByText("row-service")).toBeInTheDocument();
    expect(screen.getByText("eu-west-1")).toBeInTheDocument();
    expect(screen.getByText("row-group")).toBeInTheDocument();
    expect(screen.getByText("row-type")).toBeInTheDocument();
    expect(screen.getByText("FAIL")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.queryByText("finding-service")).not.toBeInTheDocument();
    expect(screen.queryByText("ap-south-1")).not.toBeInTheDocument();
    expect(screen.queryByText("finding-group")).not.toBeInTheDocument();
    expect(screen.queryByText("finding-type")).not.toBeInTheDocument();
  });

  it("should prefer the fetched finding status and severity in the header when the current row is stale", () => {
    // Given
    const currentResource: FindingResourceRow = {
      ...mockResourceRow,
      severity: "critical",
      status: "FAIL",
      isMuted: false,
    };
    const fetchedFinding: ResourceDrawerFinding = {
      ...mockFinding,
      severity: "low",
      status: "PASS",
      isMuted: true,
      mutedReason: "Muted after refresh",
    };

    // When
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentResource={currentResource}
        currentFinding={fetchedFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByText("PASS")).toBeInTheDocument();
    expect(screen.getByText("low")).toBeInTheDocument();
    expect(screen.queryByText("FAIL")).not.toBeInTheDocument();
    expect(screen.queryByText("critical")).not.toBeInTheDocument();
  });
});

describe("ResourceDetailDrawerContent — header skeleton while navigating", () => {
  it("should keep row-backed navigation chrome visible while hiding stale finding details during carousel navigation", () => {
    // Given
    const currentResource: FindingResourceRow = {
      ...mockResourceRow,
      checkId: mockCheckMeta.checkId,
      resourceName: "next-bucket",
      resourceUid: "next-resource-uid",
      service: "ec2",
      region: "eu-west-1",
      resourceType: "Instance",
      resourceGroup: "row-group",
      severity: "low",
      status: "PASS",
      findingId: "finding-2",
    };

    // When
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={2}
        currentResource={currentResource}
        currentFinding={mockFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByText("PASS")).toBeInTheDocument();
    expect(screen.getByText("low")).toBeInTheDocument();
    expect(screen.getByText("ec2")).toBeInTheDocument();
    expect(screen.getByText("eu-west-1")).toBeInTheDocument();
    expect(screen.getByText("row-group")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Finding Overview" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Other Findings For This Resource" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("uid-1")).not.toBeInTheDocument();
    expect(screen.queryByText("Status extended")).not.toBeInTheDocument();
    expect(screen.queryByText("FAIL")).not.toBeInTheDocument();
    expect(screen.queryByText("critical")).not.toBeInTheDocument();
  });

  it("should skeletonize stale check-level header content when navigating to a different check", () => {
    // Given
    const currentResource: FindingResourceRow = {
      ...mockResourceRow,
      checkId: "ec2_check",
      findingId: "finding-2",
      severity: "low",
      status: "PASS",
    };

    // When
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={2}
        currentResource={currentResource}
        currentFinding={mockFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByTestId("drawer-header-skeleton")).toBeInTheDocument();
    expect(screen.queryByText("S3 Check")).not.toBeInTheDocument();
    expect(screen.queryByText("PCI-DSS")).not.toBeInTheDocument();
    expect(screen.getByText("PASS")).toBeInTheDocument();
    expect(screen.getByText("low")).toBeInTheDocument();
  });

  it("should keep same-check overview sections visible while hiding stale finding-specific details during navigation", () => {
    // Given/When
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={2}
        currentResource={mockResourceRow}
        currentFinding={mockFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByText("Risk:")).toBeInTheDocument();
    expect(screen.getByText("Description:")).toBeInTheDocument();
    expect(screen.getByText("Remediation:")).toBeInTheDocument();
    expect(screen.getByText("security")).toBeInTheDocument();
    expect(screen.queryByText("Status Extended:")).not.toBeInTheDocument();
    expect(screen.queryByText("uid-1")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", {
        name: "Analyze This Finding With Lighthouse AI",
      }),
    ).not.toBeInTheDocument();
  });

  it("should keep the overview tab shell visible with section skeletons when navigating to a different check", () => {
    // Given
    const currentResource: FindingResourceRow = {
      ...mockResourceRow,
      checkId: "ec2_check",
      findingId: "finding-2",
      severity: "low",
      status: "PASS",
    };

    // When
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={2}
        currentResource={currentResource}
        currentFinding={mockFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(
      screen.getByTestId("overview-navigation-skeleton"),
    ).toBeInTheDocument();
    expect(screen.queryByText("Risk:")).not.toBeInTheDocument();
    expect(screen.queryByText("Description:")).not.toBeInTheDocument();
    expect(screen.queryByText("Remediation:")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Finding Overview" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Other Findings For This Resource" }),
    ).toBeInTheDocument();
  });

  it("should keep other findings table headers visible while skeletonizing only the rows during navigation", () => {
    // Given/When
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={2}
        currentResource={mockResourceRow}
        currentFinding={mockFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByText("Status")).toBeInTheDocument();
    expect(screen.getByText("Finding")).toBeInTheDocument();
    expect(screen.getByText("Severity")).toBeInTheDocument();
    expect(screen.getByText("Time")).toBeInTheDocument();
    expect(
      screen.getByTestId("other-findings-total-entries-skeleton"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("other-findings-navigation-skeleton"),
    ).toBeInTheDocument();
  });

  it("should keep scans labels visible while skeletonizing only the scan values during navigation", () => {
    // Given/When
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={2}
        currentResource={mockResourceRow}
        currentFinding={mockFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(
      screen.getByText("Showing the latest scan that evaluated this finding"),
    ).toBeInTheDocument();
    expect(screen.getByText("Scan Name")).toBeInTheDocument();
    expect(screen.getByText("Resources Scanned")).toBeInTheDocument();
    expect(screen.getByText("Progress")).toBeInTheDocument();
    expect(screen.getByText("Trigger")).toBeInTheDocument();
    expect(screen.getByText("State")).toBeInTheDocument();
    expect(screen.getByText("Duration")).toBeInTheDocument();
    expect(screen.getByText("Started At")).toBeInTheDocument();
    expect(screen.getByText("Completed At")).toBeInTheDocument();
    expect(screen.getByText("Launched At")).toBeInTheDocument();
    expect(screen.getByText("Scheduled At")).toBeInTheDocument();
    expect(screen.getByTestId("scans-navigation-skeleton")).toBeInTheDocument();
  });

  it("should keep the events tab shell visible while showing timeline row skeletons during navigation", () => {
    // Given/When
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={2}
        currentResource={mockResourceRow}
        currentFinding={mockFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByRole("button", { name: "Events" })).toBeInTheDocument();
    expect(
      screen.getByTestId("events-navigation-skeleton"),
    ).toBeInTheDocument();
  });
});

describe("ResourceDetailDrawerContent — other findings delta/muted indicator", () => {
  const renderWithOtherFinding = (overrides: Partial<ResourceDrawerFinding>) => {
    const otherFinding: ResourceDrawerFinding = {
      ...mockFinding,
      id: "finding-2",
      uid: "uid-2",
      checkId: "ec2_check",
      checkTitle: "EC2 Check",
      ...overrides,
    };
    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={mockFinding}
        otherFindings={[otherFinding]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );
  };

  const lastNotificationIndicatorPropsForOtherRow = () => {
    const calls = mockNotificationIndicator.mock.calls;
    // Last call corresponds to the other-finding row (current finding row renders first).
    return calls[calls.length - 1][0];
  };

  it("should forward delta='new' to the NotificationIndicator for a new other finding", () => {
    renderWithOtherFinding({ delta: "new" });

    expect(lastNotificationIndicatorPropsForOtherRow()).toMatchObject({
      delta: "new",
      isMuted: false,
      showDeltaWhenMuted: true,
    });
  });

  it("should forward delta='changed' to the NotificationIndicator for a changed other finding", () => {
    renderWithOtherFinding({ delta: "changed" });

    expect(lastNotificationIndicatorPropsForOtherRow()).toMatchObject({
      delta: "changed",
    });
  });

  it("should pass delta=undefined when the finding has delta='none'", () => {
    renderWithOtherFinding({ delta: "none" });

    expect(lastNotificationIndicatorPropsForOtherRow()).toMatchObject({
      delta: undefined,
    });
  });

  it("should forward mutedReason and keep delta when a muted other finding is also new", () => {
    renderWithOtherFinding({
      delta: "new",
      isMuted: true,
      mutedReason: "False positive",
    });

    expect(lastNotificationIndicatorPropsForOtherRow()).toMatchObject({
      delta: "new",
      isMuted: true,
      mutedReason: "False positive",
      showDeltaWhenMuted: true,
    });
  });
});
