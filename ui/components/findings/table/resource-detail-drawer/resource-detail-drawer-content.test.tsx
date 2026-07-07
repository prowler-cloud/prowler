import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  type AnchorHTMLAttributes,
  type ButtonHTMLAttributes,
  cloneElement,
  type HTMLAttributes,
  isValidElement,
  type ReactNode,
} from "react";
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
  mockUpdateFindingTriage,
  mockLoadLatestFindingTriageNote,
} = vi.hoisted(() => ({
  mockGetComplianceIcon: vi.fn((_: string) => null as string | null),
  mockGetCompliancesOverview: vi.fn(),
  mockWindowOpen: vi.fn(),
  mockClipboardWriteText: vi.fn(),
  mockSearchParamsState: { value: "" },
  mockNotificationIndicator: vi.fn(),
  mockUpdateFindingTriage: vi.fn(),
  mockLoadLatestFindingTriageNote: vi.fn(),
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
  default: ({
    children,
    href,
    prefetch: _prefetch,
    ...props
  }: AnchorHTMLAttributes<HTMLAnchorElement> & {
    children: ReactNode;
    href: string;
    prefetch?: boolean;
  }) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

// Mock the entire shadcn barrel to avoid auth import chain
vi.mock("@/components/shadcn", async (importOriginal) => {
  const Passthrough = ({ children }: { children?: ReactNode }) => (
    <>{children}</>
  );
  return {
    ...(await importOriginal<Record<string, unknown>>()),
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
    }) =>
      _asChild && isValidElement(children) ? (
        cloneElement(children, props)
      ) : (
        <button {...props}>{children}</button>
      ),
    InfoField: ({
      children,
      label,
      className,
    }: {
      children: ReactNode;
      label: string;
      variant?: string;
      className?: string;
    }) => (
      <div className={className}>
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

vi.mock("@/components/shadcn/card/card", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
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
    JSON: "json",
  },
  QueryCodeEditor: ({
    ariaLabel,
    language,
    value,
    copyValue,
    showLineNumbers = true,
  }: {
    ariaLabel: string;
    language?: string;
    value: string;
    copyValue?: string;
    showLineNumbers?: boolean;
  }) => (
    <div
      data-testid="query-code-editor"
      data-aria-label={ariaLabel}
      data-language={language}
      data-show-line-numbers={String(showLineNumbers)}
    >
      <span>{ariaLabel}</span>
      <span>{value}</span>
      <button
        type="button"
        aria-label={`Copy ${ariaLabel}`}
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

vi.mock("@/actions/findings", () => ({
  updateFindingTriage: mockUpdateFindingTriage,
  loadLatestFindingTriageNote: mockLoadLatestFindingTriageNote,
}));

vi.mock("@/components/icons", () => ({
  getComplianceIcon: mockGetComplianceIcon,
}));

vi.mock("@/components/icons/services/IconServices", () => ({
  JiraIcon: () => null,
}));

vi.mock("@/components/shadcn/code-snippet/code-snippet", () => ({
  CodeSnippet: ({
    value,
    formatter,
    ariaLabel = "Copy to clipboard",
  }: {
    value: string;
    formatter?: (value: string) => string;
    ariaLabel?: string;
  }) => (
    <div data-testid="code-snippet">
      <span>{formatter ? formatter(value) : value}</span>
      <button type="button" onClick={() => mockClipboardWriteText(value)}>
        {ariaLabel}
      </button>
    </div>
  ),
}));

vi.mock("@/components/shadcn/entities/date-with-time", () => ({
  DateWithTime: ({ dateTime }: { dateTime: string }) => <span>{dateTime}</span>,
}));

vi.mock("@/components/shadcn/entities/entity-info", () => ({
  EntityInfo: ({
    nameAction,
    idAction,
  }: {
    nameAction?: ReactNode;
    idAction?: ReactNode;
  }) =>
    nameAction || idAction ? (
      <span>
        {nameAction && (
          <span data-testid="entity-name-action">{nameAction}</span>
        )}
        {idAction && <span data-testid="entity-id-action">{idAction}</span>}
      </span>
    ) : null,
}));

vi.mock("@/components/shadcn/table", () => ({
  Table: ({ children }: { children: ReactNode }) => <table>{children}</table>,
  TableBody: ({ children }: { children: ReactNode }) => (
    <tbody>{children}</tbody>
  ),
  TableCell: ({ children, ...props }: HTMLAttributes<HTMLTableCellElement>) => (
    <td {...props}>{children}</td>
  ),
  TableHead: ({ children, ...props }: HTMLAttributes<HTMLTableCellElement>) => (
    <th {...props}>{children}</th>
  ),
  TableHeader: ({ children }: { children: ReactNode }) => (
    <thead>{children}</thead>
  ),
  TableRow: ({ children, ...props }: HTMLAttributes<HTMLTableRowElement>) => (
    <tr {...props}>{children}</tr>
  ),
}));

vi.mock("@/components/shadcn/table/severity-badge", () => ({
  SeverityBadge: ({ severity }: { severity: string }) => (
    <span>{severity}</span>
  ),
}));

vi.mock("@/components/shadcn/table/status-finding-badge", () => ({
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

vi.mock("../finding-triage-cells", () => ({
  FindingNoteActionItem: ({
    triage,
    onTriageUpdateAction,
  }: {
    triage?: {
      findingId: string;
      findingUid: string;
      triageId: string | null;
      notesCount: number;
      status: string;
      label: string;
      isMuted: boolean;
    };
    onTriageUpdateAction?: (input: {
      findingId: string;
      findingUid: string;
      triageId: string | null;
      notesCount: number;
      status: string;
      previousStatus: string;
      isMuted: boolean;
      note: string;
    }) => Promise<void>;
  }) =>
    triage ? (
      <button
        type="button"
        onClick={() =>
          onTriageUpdateAction?.({
            findingId: triage.findingId,
            findingUid: triage.findingUid,
            triageId: triage.triageId,
            notesCount: triage.notesCount,
            status: "remediating",
            previousStatus: triage.status,
            isMuted: triage.isMuted,
            note: "Investigating",
          })
        }
      >
        Add Triage Note
      </button>
    ) : null,
  FindingTriageStatusCell: ({
    triage,
    onTriageUpdateAction,
  }: {
    triage?: {
      findingId: string;
      findingUid: string;
      triageId: string | null;
      notesCount: number;
      status: string;
      label: string;
      isMuted: boolean;
    };
    onTriageUpdateAction?: (input: {
      findingId: string;
      findingUid: string;
      triageId: string | null;
      notesCount: number;
      status: string;
      previousStatus: string;
      isMuted: boolean;
    }) => Promise<void>;
  }) =>
    triage ? (
      <button
        type="button"
        aria-label="Triage status"
        onClick={() =>
          onTriageUpdateAction?.({
            findingId: triage.findingId,
            findingUid: triage.findingUid,
            triageId: triage.triageId,
            notesCount: triage.notesCount,
            status: "remediating",
            previousStatus: triage.status,
            isMuted: triage.isMuted,
          })
        }
      >
        {triage.label}
      </button>
    ) : (
      <span>-</span>
    ),
  FindingTriageStatusBadge: ({ triage }: { triage: { label: string } }) => (
    <div>
      <span>Triage:</span>
      <span>{triage.label}</span>
    </div>
  ),
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
import {
  FINDING_TRIAGE_STATUS,
  type FindingTriageSummary,
} from "@/types/findings-triage";

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

function makeTriageSummary(
  overrides?: Partial<FindingTriageSummary>,
): FindingTriageSummary {
  return {
    findingId: "finding-1",
    findingUid: "prowler-finding-uid-1",
    triageId: "triage-1",
    notesCount: 0,
    status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
    label: "Under Review",
    hasVisibleNote: false,
    isMuted: false,
    canEdit: true,
    billingHref: "https://prowler.com/pricing",
    ...overrides,
  };
}

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
  resourceDetails: null,
  resourceMetadata: null,
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

describe("ResourceDetailDrawerContent — resource navigation", () => {
  it("should render an icon-only View Resource link next to the resource name", () => {
    // Given
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
    const viewResourceLink = screen.getByRole("link", {
      name: "View Resource",
    });

    // Then
    expect(viewResourceLink).toHaveAttribute(
      "href",
      "/resources?resourceId=res-1",
    );
    expect(viewResourceLink).toHaveAttribute("target", "_blank");
    expect(viewResourceLink).toHaveAttribute("rel", "noopener noreferrer");
    // Icon-only: accessible name comes from an sr-only span, not from an
    // aria-label attribute, so the text lives in the DOM (more semantic).
    expect(viewResourceLink).toHaveAccessibleName("View Resource");
    expect(viewResourceLink).not.toHaveAttribute("aria-label");
    const srOnlyLabel = viewResourceLink.querySelector(".sr-only");
    expect(srOnlyLabel).toHaveTextContent("View Resource");
  });
});

describe("ResourceDetailDrawerContent — triage drawer actions", () => {
  it("should render Triage and Add Triage Note for other findings rows", () => {
    // Given
    const otherFinding: ResourceDrawerFinding = {
      ...mockFinding,
      id: "finding-2",
      uid: "uid-2",
      checkId: "ec2_check",
      checkTitle: "EC2 Check",
      triage: makeTriageSummary({
        findingId: "finding-2",
        findingUid: "uid-2",
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        label: "Remediating",
      }),
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

    // When
    const row = screen.getByText("EC2 Check").closest("tr");
    expect(row).not.toBeNull();

    // Then
    expect(screen.getByText("Triage")).toBeInTheDocument();
    expect(
      within(row as HTMLElement).getByRole("button", {
        name: "Triage status",
      }),
    ).toHaveTextContent("Remediating");
    expect(
      within(row as HTMLElement).getByRole("button", {
        name: "Add Triage Note",
      }),
    ).toBeInTheDocument();
    expect(
      within(row as HTMLElement).getByRole("button", { name: "Mute" }),
    ).toBeInTheDocument();
    expect(
      within(row as HTMLElement).getByRole("button", { name: "Send to Jira" }),
    ).toBeInTheDocument();
  });

  it("should keep the other findings actions cell sticky on the right edge", () => {
    // Given
    const otherFinding: ResourceDrawerFinding = {
      ...mockFinding,
      id: "finding-2",
      uid: "uid-2",
      checkId: "ec2_check",
      checkTitle: "EC2 Check",
      triage: makeTriageSummary({
        findingId: "finding-2",
        findingUid: "uid-2",
      }),
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

    // When
    const row = screen.getByText("EC2 Check").closest("tr");
    expect(row).not.toBeNull();
    const actionsCell = within(row as HTMLElement)
      .getByRole("button", { name: "Send to Jira" })
      .closest("td");

    // Then
    expect(actionsCell).toHaveClass("sticky");
    expect(actionsCell).toHaveClass("right-0");
    expect(actionsCell).toHaveClass("z-20");
    expect(actionsCell).toHaveClass("bg-bg-neutral-secondary");
    expect(actionsCell).toHaveClass("before:bg-gradient-to-r");
    expect(actionsCell).toHaveClass("before:to-bg-neutral-secondary");
  });

  it("should update simple drawer triage without using the mute refresh path", async () => {
    // Given
    const user = userEvent.setup();
    const onMuteComplete = vi.fn();
    mockUpdateFindingTriage.mockResolvedValue(undefined);

    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={{
          ...mockFinding,
          triage: makeTriageSummary(),
        }}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={onMuteComplete}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Add Triage Note" }));

    // Then
    expect(mockUpdateFindingTriage).toHaveBeenCalledWith(
      expect.objectContaining({
        findingId: "finding-1",
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        note: "Investigating",
      }),
    );
    expect(onMuteComplete).not.toHaveBeenCalled();
  });
});

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

  it("should render CLI remediation in the code editor without line numbers and copy without the visual prompt", async () => {
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
    await user.click(screen.getByRole("button", { name: "Copy CLI Command" }));

    // Then
    expect(editors).toHaveLength(3);
    expect(editors[0]).toHaveAttribute("data-aria-label", "CLI Command");
    expect(editors[0]).toHaveAttribute("data-show-line-numbers", "false");
    expect(editors[1]).toHaveAttribute("data-show-line-numbers", "true");
    expect(editors[2]).toHaveAttribute("data-show-line-numbers", "true");
    expect(mockClipboardWriteText).toHaveBeenCalledWith("aws s3 ...");
    expect(screen.getByText("$ aws s3 ...")).toBeInTheDocument();
  });

  it("should pass syntax highlighting languages to all remediation editors", () => {
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
    expect(editors).toHaveLength(3);
    expect(editors[0]).toHaveAttribute("data-language", "shell");
    expect(editors[1]).toHaveAttribute("data-language", "hcl");
    expect(editors[2]).toHaveAttribute("data-language", "yaml");
    expect(editors[0]).toHaveAttribute("data-aria-label", "CLI Command");
    expect(editors[1]).toHaveAttribute("data-aria-label", "Terraform");
    expect(editors[2]).toHaveAttribute("data-aria-label", "CloudFormation");
  });
});

describe("ResourceDetailDrawerContent — CVE recommendation button", () => {
  const statusExtendedWithFixVersions =
    "framework.security.spring-security-web@5.8.7 (fix available: 5.7.13, 5.8.15, 6.2.7, 6.0.13, 6.1.11, 6.3.4)";
  const externalCveUrl = "https://www.cve.org/CVERecord?id=CVE-2026-12345";

  it("should render a View CVE button when the recommendation URL points to an external CVE advisory and keep status extended as plain text", () => {
    const cveCheckMeta: CheckMeta = {
      ...mockCheckMeta,
      remediation: {
        ...mockCheckMeta.remediation,
        recommendation: {
          text: "Review the advisory",
          url: externalCveUrl,
        },
      },
    };
    const cveFinding: ResourceDrawerFinding = {
      ...mockFinding,
      statusExtended: statusExtendedWithFixVersions,
      remediation: {
        ...mockFinding.remediation,
        recommendation: {
          text: "Review the advisory",
          url: externalCveUrl,
        },
      },
    };

    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={cveCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={cveFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    expect(screen.getByRole("link", { name: "View CVE" })).toHaveAttribute(
      "href",
      externalCveUrl,
    );
    expect(screen.getByText(statusExtendedWithFixVersions)).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "View in Prowler Hub" }),
    ).not.toBeInTheDocument();
  });

  it("should show View in Prowler Hub when the recommendation URL points to Prowler Hub", () => {
    const hubCheckMeta: CheckMeta = {
      ...mockCheckMeta,
      remediation: {
        ...mockCheckMeta.remediation,
        recommendation: {
          text: "Open the check in Hub",
          url: "https://hub.prowler.com/check/image_vulnerability",
        },
      },
    };
    const hubFinding: ResourceDrawerFinding = {
      ...mockFinding,
      statusExtended: statusExtendedWithFixVersions,
      remediation: {
        ...mockFinding.remediation,
        recommendation: {
          text: "Open the check in Hub",
          url: "https://hub.prowler.com/check/image_vulnerability",
        },
      },
    };

    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={hubCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={hubFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    expect(screen.getByText(statusExtendedWithFixVersions)).toBeInTheDocument();
    const hubLink = screen.getByRole("link", { name: "View in Prowler Hub" });
    expect(hubLink).toHaveAttribute(
      "href",
      "https://hub.prowler.com/check/image_vulnerability",
    );
    expect(hubLink).toHaveAttribute("target", "_blank");
    expect(hubLink).toHaveAttribute("rel", "noopener noreferrer");
    const headingRow = screen.getByTestId("remediation-heading-row");
    expect(within(headingRow).getByText("Remediation:")).toBeInTheDocument();
    expect(hubLink).toHaveClass("shrink-0", "whitespace-nowrap");
    expect(
      within(headingRow).queryByText("Open the check in Hub"),
    ).not.toBeInTheDocument();
  });

  it("should render the official CVE reference", () => {
    const cveCheckMeta: CheckMeta = {
      ...mockCheckMeta,
      remediation: {
        ...mockCheckMeta.remediation,
        recommendation: {
          text: "Review the advisory",
          url: externalCveUrl,
        },
      },
      additionalUrls: [externalCveUrl],
    };
    const cveFinding: ResourceDrawerFinding = {
      ...mockFinding,
      statusExtended: statusExtendedWithFixVersions,
      remediation: {
        ...mockFinding.remediation,
        recommendation: {
          text: "Review the advisory",
          url: externalCveUrl,
        },
      },
      additionalUrls: [externalCveUrl],
    };

    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={cveCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={cveFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    expect(screen.getByRole("link", { name: "View CVE" })).toHaveAttribute(
      "href",
      externalCveUrl,
    );
    const referenceLink = screen.getByRole("link", { name: externalCveUrl });
    expect(referenceLink).toHaveAttribute("href", externalCveUrl);
    expect(referenceLink).toHaveAttribute("target", "_blank");
    expect(referenceLink).toHaveAttribute("rel", "noopener noreferrer");
    expect(referenceLink).toHaveClass("break-all", "text-left");
    expect(screen.queryByRole("list")).not.toBeInTheDocument();
  });

  it("should render View Advisory when the recommendation URL points to GitHub Security Advisories", () => {
    const advisoryUrl = "https://github.com/advisories/GHSA-abcd-1234-efgh";
    const advisoryCheckMeta: CheckMeta = {
      ...mockCheckMeta,
      remediation: {
        ...mockCheckMeta.remediation,
        recommendation: {
          text: "Review the advisory",
          url: advisoryUrl,
        },
      },
    };
    const advisoryFinding: ResourceDrawerFinding = {
      ...mockFinding,
      remediation: {
        ...mockFinding.remediation,
        recommendation: {
          text: "Review the advisory",
          url: advisoryUrl,
        },
      },
    };

    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={advisoryCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={advisoryFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    expect(screen.getByRole("link", { name: "View Advisory" })).toHaveAttribute(
      "href",
      advisoryUrl,
    );
    expect(
      screen.queryByRole("link", { name: "View CVE" }),
    ).not.toBeInTheDocument();
  });

  it("should render a remediation label when the only remediation content is a recommendation link", () => {
    const cveCheckMeta: CheckMeta = {
      ...mockCheckMeta,
      remediation: {
        ...mockCheckMeta.remediation,
        recommendation: {
          text: "",
          url: externalCveUrl,
        },
      },
    };
    const cveFinding: ResourceDrawerFinding = {
      ...mockFinding,
      remediation: {
        ...mockFinding.remediation,
        recommendation: {
          text: "",
          url: externalCveUrl,
        },
      },
    };

    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={cveCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={cveFinding}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    expect(screen.getByText("Remediation:")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View CVE" })).toHaveAttribute(
      "href",
      externalCveUrl,
    );
  });
});

// ---------------------------------------------------------------------------
// Fix 5 & 6: Risk section has danger styling, sections have separators and bigger headings
// ---------------------------------------------------------------------------

describe("ResourceDetailDrawerContent — Risk section styling", () => {
  it("should render the Risk section with a vertical accent border (no danger card)", () => {
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

    // When — find the Risk heading and walk up to the section wrapper
    const riskHeading = Array.from(container.querySelectorAll("span")).find(
      (el) => el.textContent?.trim() === "Risk:",
    );
    const riskSection = riskHeading?.parentElement;

    // Then — Risk wrapper has a left accent border, not a danger Card
    expect(riskSection).toBeDefined();
    expect(riskSection?.className).toMatch(/border-l/);
    expect(riskSection?.getAttribute("data-variant")).toBeNull();
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
  it("should place service and region in the primary metadata row after provider and resource", () => {
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
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    const primaryMetadataRow = screen.getByTestId(
      "resource-detail-primary-metadata-row",
    );
    expect(primaryMetadataRow).toHaveClass("grid-cols-2");
    expect(primaryMetadataRow).toHaveClass(
      "@md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,0.55fr)_minmax(0,0.7fr)]",
    );
    expect(
      within(primaryMetadataRow).getByText("Provider"),
    ).toBeInTheDocument();
    expect(
      within(primaryMetadataRow).getByText("Resource"),
    ).toBeInTheDocument();
    expect(within(primaryMetadataRow).getByText("Service")).toBeInTheDocument();
    expect(within(primaryMetadataRow).getByText("Region")).toBeInTheDocument();
    expect(within(primaryMetadataRow).getByText("s3")).toHaveClass(
      "truncate",
      "whitespace-nowrap",
    );
    expect(within(primaryMetadataRow).getByText("us-east-1")).toHaveClass(
      "truncate",
    );

    const secondaryMetadataRow = screen.getByTestId(
      "resource-detail-secondary-metadata-row",
    );
    expect(secondaryMetadataRow).toHaveClass("grid-cols-2");
    expect(secondaryMetadataRow).toHaveClass("@md:grid-cols-3");
    expect(
      within(secondaryMetadataRow).queryByText("Service"),
    ).not.toBeInTheDocument();
    expect(
      within(secondaryMetadataRow).queryByText("Region"),
    ).not.toBeInTheDocument();
    expect(within(secondaryMetadataRow).getByText("2 days")).toHaveClass(
      "truncate",
      "whitespace-nowrap",
    );
  });

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
    expect(screen.getByText("FAIL")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.queryByText("finding-service")).not.toBeInTheDocument();
    expect(screen.queryByText("ap-south-1")).not.toBeInTheDocument();
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
    expect(
      screen.getByRole("button", { name: "Overview" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Other findings" }),
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
      screen.getByRole("button", { name: "Overview" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Other findings" }),
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
  const renderWithOtherFinding = (
    overrides: Partial<ResourceDrawerFinding>,
  ) => {
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

describe("ResourceDetailDrawerContent — Metadata tab", () => {
  const getMetadataEditor = () =>
    screen
      .queryAllByTestId("query-code-editor")
      .find(
        (editor) =>
          editor.getAttribute("data-aria-label") === "Resource metadata",
      );

  it("should render a Metadata tab trigger", () => {
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
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(
      screen.getByRole("button", { name: "Evidence" }),
    ).toBeInTheDocument();
  });

  it("should render the resource metadata as formatted JSON and copy it to the clipboard", async () => {
    // Given
    const user = userEvent.setup();
    const findingWithMetadata: ResourceDrawerFinding = {
      ...mockFinding,
      resourceDetails: "Python",
      resourceMetadata: {
        VulnerabilityID: "CVE-2026-0001",
        PkgName: "requests",
      },
    };

    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={findingWithMetadata}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then — Details section + JSON editor are rendered
    expect(screen.getByText("Details:")).toBeInTheDocument();
    expect(screen.getByText("Python")).toBeInTheDocument();

    const metadataEditor = getMetadataEditor();
    expect(metadataEditor).toBeDefined();
    expect(metadataEditor).toHaveAttribute("data-language", "json");
    expect(metadataEditor?.textContent).toContain("CVE-2026-0001");

    // When — copy the metadata JSON
    await user.click(
      screen.getByRole("button", { name: "Copy Resource metadata" }),
    );

    // Then
    expect(mockClipboardWriteText).toHaveBeenCalledWith(
      JSON.stringify(findingWithMetadata.resourceMetadata, null, 2),
    );
  });

  it("should parse stringified resource metadata", () => {
    // Given
    const findingWithStringMetadata: ResourceDrawerFinding = {
      ...mockFinding,
      resourceMetadata: '{"PkgName":"requests"}',
    };

    render(
      <ResourceDetailDrawerContent
        isLoading={false}
        isNavigating={false}
        checkMeta={mockCheckMeta}
        currentIndex={0}
        totalResources={1}
        currentFinding={findingWithStringMetadata}
        otherFindings={[]}
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(getMetadataEditor()?.textContent).toContain("requests");
  });

  it("should show an empty state when no metadata or details are available", () => {
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
        onNavigatePrev={vi.fn()}
        onNavigateNext={vi.fn()}
        onMuteComplete={vi.fn()}
      />,
    );

    // Then
    expect(
      screen.getByText("No metadata available for this resource."),
    ).toBeInTheDocument();
    expect(getMetadataEditor()).toBeUndefined();
  });

  it("should show a metadata skeleton while navigating", () => {
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
      screen.getByTestId("metadata-navigation-skeleton"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("No metadata available for this resource."),
    ).not.toBeInTheDocument();
  });
});
