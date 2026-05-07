import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ALERT_AGGREGATE_OPS,
  ALERT_BOOLEAN_OPS,
  ALERT_RECIPIENT_STATUS,
  ALERT_TRIGGER_KINDS,
  type AlertCondition,
  type AlertRecipient,
  type AlertRule,
} from "@/app/(prowler)/alerts/_types";
import type { ProviderProps } from "@/types/providers";

import { AlertFormModal } from "../alert-form-modal";

const recipientsActionMocks = vi.hoisted(() => ({
  listAlertRecipients: vi.fn(),
}));

const alertsActionMocks = vi.hoisted(() => ({
  previewAlertCondition: vi.fn(),
  seedAlertRule: vi.fn(),
}));

vi.mock(
  "@/app/(prowler)/alerts/_actions/recipients",
  () => recipientsActionMocks,
);

vi.mock("@/app/(prowler)/alerts/_actions", () => alertsActionMocks);

vi.mock(
  "@/components/compliance/compliance-header/compliance-scan-info",
  () => ({
    ComplianceScanInfo: () => <span>Scan</span>,
  }),
);

vi.mock("@/components/ui/entities/entity-info", () => ({
  EntityInfo: ({
    entityAlias,
    entityId,
  }: {
    entityAlias?: string;
    entityId?: string;
  }) => <span>{entityAlias ?? entityId}</span>,
}));

vi.mock("next-auth/react", () => ({
  useSession: () => ({ data: null, status: "unauthenticated" }),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/alerts",
  useRouter: () => ({ replace: vi.fn(), push: vi.fn(), refresh: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/components/shadcn/modal", () => ({
  Modal: ({
    open,
    title,
    description,
    className,
    onOpenAutoFocus,
    children,
  }: {
    open: boolean;
    title?: string;
    description?: string;
    className?: string;
    onOpenAutoFocus?: (event: Event) => void;
    children: ReactNode;
  }) =>
    open ? (
      <div
        role="dialog"
        aria-label={title}
        aria-description={description}
        className={className}
        data-allows-open-auto-focus={String(Boolean(onOpenAutoFocus))}
      >
        {children}
      </div>
    ) : null,
}));

class ResizeObserverMock {
  observe = vi.fn();
  unobserve = vi.fn();
  disconnect = vi.fn();
}

global.ResizeObserver = ResizeObserverMock;
Element.prototype.scrollIntoView = vi.fn();

const mockProviders: ProviderProps[] = [
  {
    id: "provider-aws-1",
    type: "providers",
    attributes: {
      provider: "aws",
      uid: "123456789012",
      alias: "Production AWS",
      status: "completed",
      resources: 42,
      connection: {
        connected: true,
        last_checked_at: "2026-04-30T00:00:00Z",
      },
      scanner_args: {
        only_logs: false,
        excluded_checks: [],
        aws_retries_max_attempts: 3,
      },
      inserted_at: "2026-04-30T00:00:00Z",
      updated_at: "2026-04-30T00:00:00Z",
      created_by: { object: "users", id: "user-1" },
    },
    relationships: {
      secret: { data: null },
      provider_groups: { meta: { count: 0 }, data: [] },
    },
  },
  {
    id: "provider-gcp-1",
    type: "providers",
    attributes: {
      provider: "gcp",
      uid: "prowler-prod-project",
      alias: "Production GCP",
      status: "completed",
      resources: 21,
      connection: {
        connected: true,
        last_checked_at: "2026-04-30T00:00:00Z",
      },
      scanner_args: {
        only_logs: false,
        excluded_checks: [],
        aws_retries_max_attempts: 3,
      },
      inserted_at: "2026-04-30T00:00:00Z",
      updated_at: "2026-04-30T00:00:00Z",
      created_by: { object: "users", id: "user-1" },
    },
    relationships: {
      secret: { data: null },
      provider_groups: { meta: { count: 0 }, data: [] },
    },
  },
];

const createRecipient = (
  id: string,
  email: string,
  status: AlertRecipient["attributes"]["status"],
): AlertRecipient => ({
  id,
  type: "alert-recipients",
  attributes: {
    email,
    status,
    inserted_at: "2026-04-30T00:00:00Z",
    updated_at: "2026-04-30T00:00:00Z",
  },
  relationships: { rules: { data: [] } },
});

const confirmedRecipient = createRecipient(
  "recipient-confirmed",
  "security@example.com",
  ALERT_RECIPIENT_STATUS.CONFIRMED,
);

const pendingRecipient = createRecipient(
  "recipient-pending",
  "pending@example.com",
  ALERT_RECIPIENT_STATUS.PENDING,
);

const createEditingAlert = (
  overrides: Partial<AlertRule["attributes"]> = {},
): AlertRule => ({
  id: "alert-1",
  type: "alert-rules",
  attributes: {
    name: "Existing alert",
    description: "Existing description",
    enabled: true,
    trigger: ALERT_TRIGGER_KINDS.AFTER_SCAN,
    condition: {
      op: ALERT_AGGREGATE_OPS.COUNT_GTE,
      filter: { severity: ["critical"] },
      value: 1,
    },
    schema_version: 1,
    recipient_emails: ["security@example.com"],
    inserted_at: "2026-04-30T00:00:00Z",
    updated_at: "2026-04-30T00:00:00Z",
    ...overrides,
  },
});

const mockRecipientsList = () => {
  recipientsActionMocks.listAlertRecipients.mockResolvedValue({
    data: [confirmedRecipient, pendingRecipient],
    meta: { pagination: { page: 1, pages: 1, count: 2 } },
  });
};

const renderCreateModal = (
  props: Partial<React.ComponentProps<typeof AlertFormModal>> = {},
) =>
  render(
    <AlertFormModal
      open
      defaultFrequency={ALERT_TRIGGER_KINDS.AFTER_SCAN}
      onOpenChange={vi.fn()}
      onSubmit={vi.fn()}
      {...props}
    />,
  );

const getVisibleFilterTrigger = (label: string): HTMLButtonElement => {
  const trigger = screen
    .getAllByRole("combobox")
    .find(
      (element) =>
        element.textContent?.includes(label) &&
        !element.closest('[aria-hidden="true"]'),
    );

  expect(trigger).toBeDefined();
  return trigger as HTMLButtonElement;
};

describe("AlertFormModal", () => {
  beforeEach(() => {
    recipientsActionMocks.listAlertRecipients.mockReset();
    recipientsActionMocks.listAlertRecipients.mockReturnValue(
      new Promise(() => {}),
    );
    alertsActionMocks.previewAlertCondition.mockReset();
    alertsActionMocks.seedAlertRule.mockReset();
    alertsActionMocks.seedAlertRule.mockResolvedValue({
      data: {
        attributes: {
          condition: {
            op: ALERT_AGGREGATE_OPS.ANY,
            filter: { provider_type: ["gcp"] },
          },
          schema_version: 1,
          warnings: [],
        },
      },
    });
  });

  it("should render the simplified alert form without preview, delivery settings, or nested recipient management", () => {
    // Given / When
    renderCreateModal({
      providers: mockProviders,
      uniqueRegions: ["us-east-1", "europe-west1"],
      uniqueServices: ["iam", "cloudsql"],
      uniqueCategories: ["identity-security"],
      uniqueGroups: ["prod"],
    });

    // Then
    expect(screen.getByRole("dialog", { name: "Create Alert" })).toBeVisible();
    expect(screen.getByLabelText(/^name$/i)).toBeVisible();
    expect(screen.getByLabelText(/^description$/i)).toBeVisible();
    expect(screen.getByLabelText(/^frequency$/i)).toBeVisible();
    expect(screen.getByLabelText(/^recipients$/i)).toBeVisible();
    expect(screen.getAllByRole("combobox")).toHaveLength(2);
    expect(screen.queryByText("Alert criteria")).not.toBeInTheDocument();
    expect(screen.queryByText(/delivery settings/i)).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText(/notification method/i),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/run preview/i)).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /manage recipients/i }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Production AWS")).not.toBeInTheDocument();
    expect(screen.queryByText(/resource type/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^date$/i)).not.toBeInTheDocument();
  });

  it("should provide accessible dialog description and allow initial focus when editing", () => {
    // Given / When
    renderCreateModal({
      editingAlert: createEditingAlert(),
    });

    // Then
    const dialog = screen.getByRole("dialog", { name: "Edit Alert" });
    expect(dialog).toHaveAccessibleDescription(
      "Update recipients, frequency, and finding filters for this alert.",
    );
    expect(dialog).toHaveAttribute("data-allows-open-auto-focus", "true");
  });

  it("should show selected Findings filters as chips while keeping criteria controls hidden", () => {
    // Given / When
    renderCreateModal({
      seededCondition: {
        op: ALERT_AGGREGATE_OPS.ANY,
        filter: { severity: ["critical"] },
      },
      selectedFindingsFilterChips: [
        { key: "filter[status__in]", label: "Status", value: "FAIL" },
        { key: "filter[muted]", label: "Muted", value: "false" },
      ],
    });

    // Then
    expect(
      screen.getByRole("region", { name: /active filters/i }),
    ).toHaveTextContent("Status: FAIL");
    expect(
      screen.getByRole("region", { name: /active filters/i }),
    ).toHaveTextContent("Muted: false");
    expect(screen.queryByText("All Provider")).not.toBeInTheDocument();
    expect(screen.queryByText(/run preview/i)).not.toBeInTheDocument();
  });

  it("should list tenant recipients with status and submit selected emails", async () => {
    // Given
    const user = userEvent.setup();
    const onSubmit = vi
      .fn()
      .mockResolvedValue({ ok: true, alertId: "alert-1" });
    mockRecipientsList();
    renderCreateModal({ onSubmit });

    // When
    await user.type(screen.getByLabelText(/^name$/i), "Critical alerts");
    await user.click(getVisibleFilterTrigger("Select emails"));
    expect((await screen.findAllByText("Confirmed")).at(-1)).toBeVisible();
    expect(screen.getAllByText("Pending").at(-1)).toBeVisible();
    const recipientOptions = await screen.findAllByText("pending@example.com");
    const visibleRecipientOption = recipientOptions.at(-1);
    expect(visibleRecipientOption).toBeDefined();
    await user.click(visibleRecipientOption as HTMLElement);
    await user.click(screen.getByRole("button", { name: /^create$/i }));

    // Then
    expect(screen.getAllByText("pending@example.com").at(-1)).toBeVisible();
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          frequency: ALERT_TRIGGER_KINDS.AFTER_SCAN,
          recipientEmails: ["pending@example.com"],
        }),
      ),
    );
    const recipientsParams = recipientsActionMocks.listAlertRecipients.mock
      .calls[0][0] as Record<string, string>;
    expect(recipientsParams["filter[status]"]).toBeUndefined();
    expect(recipientsParams["page[size]"]).toBe("100");
  });

  it("should submit the configured alert frequency", async () => {
    // Given
    const user = userEvent.setup();
    const onSubmit = vi
      .fn()
      .mockResolvedValue({ ok: true, alertId: "alert-1" });
    mockRecipientsList();
    renderCreateModal({
      defaultFrequency: ALERT_TRIGGER_KINDS.DAILY,
      onSubmit,
    });

    // When
    await user.type(screen.getByLabelText(/^name$/i), "Daily alerts");
    expect(
      screen.getByRole("combobox", { name: /frequency/i }),
    ).toHaveTextContent("Daily digest");
    await user.click(getVisibleFilterTrigger("Select emails"));
    const recipientOptions = await screen.findAllByText("security@example.com");
    const visibleRecipientOption = recipientOptions.at(-1);
    expect(visibleRecipientOption).toBeDefined();
    await user.click(visibleRecipientOption as HTMLElement);
    await user.click(screen.getByRole("button", { name: /^create$/i }));

    // Then
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          frequency: ALERT_TRIGGER_KINDS.DAILY,
        }),
      ),
    );
  });

  it("should allow submitting without selected recipients", async () => {
    // Given
    const user = userEvent.setup();
    const onSubmit = vi
      .fn()
      .mockResolvedValue({ ok: true, alertId: "alert-1" });
    mockRecipientsList();
    renderCreateModal({ onSubmit });

    // When
    await user.type(screen.getByLabelText(/^name$/i), "Critical alerts");
    await user.click(screen.getByRole("button", { name: /^create$/i }));

    // Then
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          recipientEmails: [],
        }),
      ),
    );
    expect(
      screen.queryByText(/select at least one recipient/i),
    ).not.toBeInTheDocument();
  });

  it("should render backend submit errors with the design error color", async () => {
    // Given
    const user = userEvent.setup();
    const onSubmit = vi.fn().mockResolvedValue({
      ok: false,
      error: "Backend validation failed",
    });
    mockRecipientsList();
    renderCreateModal({ onSubmit });

    // When
    await user.type(screen.getByLabelText(/^name$/i), "Critical alerts");
    await user.click(screen.getByRole("button", { name: /^create$/i }));

    // Then
    const errorMessage = await screen.findByText("Backend validation failed");
    expect(errorMessage).toHaveClass("text-text-error-primary");
  });

  it("should reset form defaults when opening a different alert", () => {
    // Given
    const { rerender } = render(
      <AlertFormModal
        open
        defaultFrequency={ALERT_TRIGGER_KINDS.AFTER_SCAN}
        editingAlert={createEditingAlert({ name: "First alert" })}
        onOpenChange={vi.fn()}
        onSubmit={vi.fn()}
      />,
    );

    // When
    rerender(
      <AlertFormModal
        open
        defaultFrequency={ALERT_TRIGGER_KINDS.AFTER_SCAN}
        editingAlert={createEditingAlert({
          name: "Second alert",
          updated_at: "2026-05-01T00:00:00Z",
        })}
        onOpenChange={vi.fn()}
        onSubmit={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByLabelText(/^name$/i)).toHaveValue("Second alert");
  });

  it("should render the shared Findings batch filter controls for an existing alert", async () => {
    // Given
    mockRecipientsList();
    renderCreateModal({
      editingAlert: createEditingAlert({
        condition: {
          op: ALERT_BOOLEAN_OPS.AND,
          children: [
            {
              op: ALERT_AGGREGATE_OPS.COUNT_GTE,
              filter: { severity: ["critical"] },
              value: 1,
            },
            {
              op: ALERT_AGGREGATE_OPS.COUNT_GTE,
              filter: { provider_type: ["aws"] },
              value: 1,
            },
          ],
        },
      }),
      providers: mockProviders,
      uniqueRegions: ["us-east-1", "europe-west1"],
      uniqueServices: ["iam", "cloudsql"],
      uniqueResourceTypes: ["AWS::IAM::User"],
      uniqueCategories: ["identity-security"],
      uniqueGroups: ["prod"],
    });

    // Then
    const recipientsTrigger = screen.getByLabelText(/^recipients$/i);
    const filtersHeading = screen.getByRole("heading", { name: /^filters$/i });

    expect(filtersHeading).toBeVisible();
    expect(
      recipientsTrigger.compareDocumentPosition(filtersHeading) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(filtersHeading.closest('[data-slot="card"]')).toBeVisible();
    const filterControls = screen.getByTestId("findings-filter-controls");
    const alertEditGrid = filterControls.querySelector(".grid");
    expect(alertEditGrid).toHaveClass("xl:grid-cols-3", "2xl:grid-cols-3");
    expect(alertEditGrid).not.toHaveClass("xl:grid-cols-4", "2xl:grid-cols-5");
    expect(screen.getAllByText("Amazon Web Services")[0]).toBeVisible();
    expect(screen.getByText("All accounts")).toBeVisible();
    expect(within(filterControls).getByText("All Delta")).toBeVisible();
    expect(within(filterControls).getByText("All Resource Type")).toBeVisible();
    expect(
      screen.queryByTestId("findings-expanded-filters"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /more filters/i }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("All Status")).not.toBeInTheDocument();
    expect(screen.queryByText("Scan ID")).not.toBeInTheDocument();
    expect(screen.queryByText(/^date$/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^severity$/i)).not.toBeInTheDocument();
  });

  it("should save edited filters as a normalized simple condition", async () => {
    // Given
    const user = userEvent.setup();
    const onSubmit = vi
      .fn()
      .mockResolvedValue({ ok: true, alertId: "alert-1" });
    mockRecipientsList();
    renderCreateModal({
      editingAlert: createEditingAlert(),
      providers: mockProviders,
      onSubmit,
    });

    // When
    await user.click(screen.getByLabelText(/provider type/i));
    const providerOptions = await screen.findAllByText("Google Cloud Platform");
    const visibleProviderOption = providerOptions.at(-1);
    expect(visibleProviderOption).toBeDefined();
    await user.click(visibleProviderOption as HTMLElement);
    await user.click(screen.getByRole("button", { name: /^save$/i }));

    // Then
    await waitFor(() =>
      expect(alertsActionMocks.seedAlertRule).toHaveBeenCalled(),
    );
    expect(alertsActionMocks.seedAlertRule).toHaveBeenCalledWith(
      expect.objectContaining({
        "filter[provider_type__in]": ["gcp"],
      }),
    );
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          condition: expect.objectContaining({
            filter: { provider_type: ["gcp"] },
          }),
        }),
      ),
    );
  });

  it("should preview the edited alert using current unsaved filters", async () => {
    // Given
    const user = userEvent.setup();
    alertsActionMocks.previewAlertCondition.mockResolvedValue({
      data: {
        attributes: {
          summary: {
            finding_count_total: 7,
            top_severity: "critical",
          },
          sample_finding_ids: [],
          evaluation_failed: false,
          duration_ms: 42,
        },
      },
    });
    mockRecipientsList();
    renderCreateModal({
      editingAlert: createEditingAlert(),
      providers: mockProviders,
    });

    // When
    await user.click(screen.getByLabelText(/provider type/i));
    const providerOptions = await screen.findAllByText("Google Cloud Platform");
    const visibleProviderOption = providerOptions.at(-1);
    expect(visibleProviderOption).toBeDefined();
    await user.click(visibleProviderOption as HTMLElement);
    await user.click(screen.getByRole("button", { name: /^test$/i }));

    // Then
    await waitFor(() =>
      expect(alertsActionMocks.seedAlertRule).toHaveBeenCalledWith(
        expect.objectContaining({
          "filter[provider_type__in]": ["gcp"],
        }),
      ),
    );
    await waitFor(() =>
      expect(alertsActionMocks.previewAlertCondition).toHaveBeenCalledWith(
        expect.objectContaining({
          condition: expect.objectContaining({
            filter: { provider_type: ["gcp"] },
          }),
        }),
      ),
    );
    const previewHeading = await screen.findByText("Test result");
    expect(previewHeading).toBeVisible();
    const previewCard = previewHeading.closest('[data-slot="card"]');
    expect(previewCard).toBeInTheDocument();
    const previewCardQueries = within(previewCard as HTMLElement);
    expect(
      previewCardQueries.getByText(
        "It found 7 findings, including Critical severity.",
      ),
    ).toBeVisible();
    expect(
      previewCardQueries.queryByText(/^findings$/i),
    ).not.toBeInTheDocument();
    expect(
      previewCardQueries.queryByText(/^top severity$/i),
    ).not.toBeInTheDocument();
    expect(
      previewCardQueries.queryByText(/^duration$/i),
    ).not.toBeInTheDocument();
    expect(previewCardQueries.queryByText(/42 ms/i)).not.toBeInTheDocument();
    expect(
      previewCardQueries.queryByText("Would fire"),
    ).not.toBeInTheDocument();
    expect(
      previewCardQueries.queryByText("Would not fire"),
    ).not.toBeInTheDocument();
  });

  it("should explain when the edited alert has no matching findings", async () => {
    // Given
    const user = userEvent.setup();
    alertsActionMocks.previewAlertCondition.mockResolvedValue({
      data: {
        attributes: {
          summary: {
            finding_count_total: 0,
          },
          sample_finding_ids: [],
          evaluation_failed: false,
        },
      },
    });
    mockRecipientsList();
    renderCreateModal({ editingAlert: createEditingAlert() });

    // When
    await user.click(screen.getByRole("button", { name: /^test$/i }));

    // Then
    expect(
      await screen.findByText(
        "These filters did not match any findings for the latest scan.",
      ),
    ).toBeVisible();
    expect(screen.queryByText("Would fire")).not.toBeInTheDocument();
    expect(screen.queryByText("Would not fire")).not.toBeInTheDocument();
  });

  it("should render preview errors inline in edit mode", async () => {
    // Given
    const user = userEvent.setup();
    alertsActionMocks.previewAlertCondition.mockResolvedValue({
      error: "Invalid condition",
    });
    mockRecipientsList();
    renderCreateModal({ editingAlert: createEditingAlert() });

    // When
    await user.click(screen.getByRole("button", { name: /^test$/i }));

    // Then
    const errorMessage = await screen.findByText(/invalid condition/i);
    expect(errorMessage).toBeVisible();
    expect(errorMessage).toHaveClass("text-text-error-primary");
  });

  it("should hydrate advanced edit mode filters and normalize them on save", async () => {
    // Given
    const user = userEvent.setup();
    const advancedCondition: AlertCondition = {
      op: ALERT_BOOLEAN_OPS.NOT,
      child: {
        op: ALERT_AGGREGATE_OPS.COUNT_GTE,
        filter: { severity: ["critical"] },
        value: 1,
      },
    };
    const onSubmit = vi
      .fn()
      .mockResolvedValue({ ok: true, alertId: "alert-1" });
    alertsActionMocks.seedAlertRule.mockResolvedValue({
      data: {
        attributes: {
          condition: {
            op: ALERT_AGGREGATE_OPS.ANY,
            filter: { severity: ["critical"] },
          },
          schema_version: 1,
          warnings: [],
        },
      },
    });
    mockRecipientsList();
    renderCreateModal({
      editingAlert: createEditingAlert({
        condition: advancedCondition,
        recipient_emails: ["security@example.com"],
      }),
      onSubmit,
    });

    // When
    await user.click(screen.getByRole("button", { name: /^save$/i }));

    // Then
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "Existing alert",
          recipientEmails: ["security@example.com"],
          condition: {
            op: ALERT_AGGREGATE_OPS.ANY,
            filter: { severity: ["critical"] },
          },
        }),
      ),
    );
    expect(
      screen.queryByText(/advanced condition preserved/i),
    ).not.toBeInTheDocument();
  });
});
