"use client";

import { useState } from "react";

import {
  previewAlertCondition,
  seedAlertRule,
} from "@/app/(prowler)/alerts/_actions";
import { listAlertRecipients } from "@/app/(prowler)/alerts/_actions/recipients";
import {
  ALERT_TRIGGER_KINDS,
  type AlertCondition,
  type AlertPreviewResponse,
  type AlertRecipient,
  type AlertRule,
  type AlertTriggerKind,
} from "@/app/(prowler)/alerts/_types";
import type { FilterChip } from "@/components/filters/filter-summary-strip";
import { FilterSummaryStrip } from "@/components/filters/filter-summary-strip";
import { FindingsFilterBatchControls } from "@/components/findings/findings-filters";
import {
  Badge,
  Button,
  Card,
  CardContent,
  Field,
  FieldError,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Skeleton,
  Textarea,
} from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectSelectAll,
  MultiSelectSeparator,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { useMountEffect } from "@/hooks/use-mount-effect";
import type { ScanEntity } from "@/types";
import type { ProviderProps } from "@/types/providers";

import {
  getAlertFormDefaults,
  getEmptyAlertFormDefaults,
  getFindingsFiltersFromAlertCondition,
} from "../_lib/alert-adapter";
import { alertFormSchema } from "../_lib/alert-form-schema";
import type {
  AlertFormSubmitResult,
  AlertFormValues,
} from "../_types/alert-form";
import { ALERT_NOTIFICATION_METHODS } from "../_types/alert-form";

interface AlertFormModalProps {
  open: boolean;
  defaultFrequency: AlertTriggerKind;
  providers?: ProviderProps[];
  completedScanIds?: string[];
  scanDetails?: { [key: string]: ScanEntity }[];
  uniqueRegions?: string[];
  uniqueServices?: string[];
  uniqueResourceTypes?: string[];
  uniqueCategories?: string[];
  uniqueGroups?: string[];
  editingAlert?: AlertRule | null;
  seededCondition?: AlertCondition | null;
  selectedFindingsFilterChips?: FilterChip[];
  defaultName?: string;
  onOpenChange: (open: boolean) => void;
  onSubmit: (values: AlertFormValues) => Promise<AlertFormSubmitResult>;
}

interface FormErrors {
  name?: string;
  recipientEmails?: string;
  root?: string;
}

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

const getRecipientEmails = (selectedEmails: Set<string>): string[] =>
  Array.from(selectedEmails);

const ALERT_FREQUENCY_OPTIONS = [
  {
    value: ALERT_TRIGGER_KINDS.AFTER_SCAN,
    label: "After each scan",
  },
  {
    value: ALERT_TRIGGER_KINDS.DAILY,
    label: "Daily digest",
  },
  {
    value: ALERT_TRIGGER_KINDS.BOTH,
    label: "After each scan and daily",
  },
] as const;

const ALERT_SEED_ERROR = "Apply at least one alert-compatible Findings filter.";

const serializeCondition = (condition: AlertCondition | null): string =>
  condition ? JSON.stringify(condition) : "none";

const getAlertFormModalResetKey = ({
  open,
  defaultFrequency,
  editingAlert,
  seededCondition,
}: Pick<
  AlertFormModalProps,
  "open" | "defaultFrequency" | "editingAlert" | "seededCondition"
>): string =>
  [
    open ? "open" : "closed",
    editingAlert?.id ?? "create",
    editingAlert?.attributes.updated_at ?? "",
    defaultFrequency,
    serializeCondition(seededCondition ?? null),
  ].join("|");

const allowInitialDialogFocus = () => undefined;

const uniqueValues = (values: string[]): string[] =>
  Array.from(new Set(values));

interface PreviewState {
  status: "success" | "error";
  data?: AlertPreviewResponse;
  error?: string;
}

const formatPreviewNumber = (value: number): string =>
  new Intl.NumberFormat("en-US").format(value);

const getPreviewSeverityLabel = (severity: string): string =>
  severity.charAt(0).toUpperCase() + severity.slice(1);

const getPreviewMessage = (data: AlertPreviewResponse): string => {
  if (!data.would_fire) {
    return "These filters did not find matching findings.";
  }

  const totalFindings = data.summary.finding_count_total ?? 0;
  const findingLabel = totalFindings === 1 ? "finding" : "findings";
  const topSeverity = data.summary.top_severity;
  const severityClause = topSeverity
    ? `, including ${getPreviewSeverityLabel(topSeverity)} severity`
    : "";

  return `It found ${formatPreviewNumber(totalFindings)} ${findingLabel}${severityClause}.`;
};

const PreviewSummarySkeleton = () => (
  <Card variant="inner" padding="sm">
    <CardContent className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <Skeleton className="h-5 w-28" />
        <Skeleton className="h-5 w-20 rounded-full" />
      </div>
      <Skeleton className="h-4 w-full" />
    </CardContent>
  </Card>
);

const PreviewSummary = ({ preview }: { preview: PreviewState }) => {
  if (preview.status === "error") {
    return (
      <Card variant="danger" padding="sm">
        <CardContent className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-2">
            <span className="text-text-neutral-primary text-sm font-medium">
              Test result
            </span>
            <Badge variant="tag">Error</Badge>
          </div>
          <p className="text-text-error-primary text-sm">{preview.error}</p>
        </CardContent>
      </Card>
    );
  }

  const data = preview.data;
  if (!data) return null;

  const statusLabel = data.would_fire ? "Would fire" : "Would not fire";

  return (
    <Card variant="inner" padding="sm">
      <CardContent className="flex flex-col gap-2">
        <div className="flex items-center justify-between gap-2">
          <span className="text-text-neutral-primary text-sm font-medium">
            Test result
          </span>
          <Badge variant="tag">{statusLabel}</Badge>
        </div>
        <p className="text-text-neutral-secondary text-sm">
          {getPreviewMessage(data)}
        </p>
      </CardContent>
    </Card>
  );
};

const normalizeFindingsFilterKey = (filterKey: string): string =>
  filterKey.startsWith("filter[") ? filterKey : `filter[${filterKey}]`;

interface AlertRecipientsSelectProps {
  selectedEmails: Set<string>;
  onValuesChange: (emails: string[]) => void;
}

interface RecipientOption {
  email: string;
  status?: AlertRecipient["attributes"]["status"];
}

const getRecipientStatusLabel = (
  status: AlertRecipient["attributes"]["status"],
): string => status.charAt(0).toUpperCase() + status.slice(1);

const getRecipientOptions = (
  recipients: AlertRecipient[],
  selectedEmails: string[],
): RecipientOption[] => {
  const options = new Map<string, RecipientOption>();

  recipients.forEach((recipient) => {
    const email = normalizeEmail(recipient.attributes.email);
    if (!email) return;
    options.set(email, { email, status: recipient.attributes.status });
  });

  selectedEmails.forEach((email) => {
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail || options.has(normalizedEmail)) return;
    options.set(normalizedEmail, { email: normalizedEmail });
  });

  return Array.from(options.values()).sort((left, right) =>
    left.email.localeCompare(right.email),
  );
};

const AlertRecipientsSelect = ({
  selectedEmails,
  onValuesChange,
}: AlertRecipientsSelectProps) => {
  const [recipients, setRecipients] = useState<AlertRecipient[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useMountEffect(() => {
    listAlertRecipients({
      "page[size]": "100",
      sort: "email",
    }).then((result) => {
      setLoading(false);
      if (result?.error) {
        setRecipients([]);
        setError(result.error);
        return;
      }
      setRecipients(result.data);
      setError(null);
    });
  });

  const selectedValues = Array.from(selectedEmails);
  const options = getRecipientOptions(recipients, selectedValues);

  return (
    <div className="flex flex-col gap-2">
      <MultiSelect values={selectedValues} onValuesChange={onValuesChange}>
        <MultiSelectTrigger
          id="alert-recipients"
          aria-label="Recipients"
          size="default"
        >
          <MultiSelectValue
            placeholder={loading ? "Loading recipients" : "Select emails"}
          />
        </MultiSelectTrigger>
        <MultiSelectContent
          search={{
            placeholder: "Search recipients...",
            emptyMessage: "No confirmed recipients found.",
          }}
          width="wide"
        >
          <MultiSelectSelectAll
            mode="select"
            values={options.map((option) => option.email)}
          >
            Select All
          </MultiSelectSelectAll>
          <MultiSelectSeparator />
          {options.map((option) => (
            <MultiSelectItem
              key={option.email}
              value={option.email}
              badgeLabel={option.email}
              keywords={[option.email, option.status ?? ""]}
            >
              <span className="truncate">{option.email}</span>
              {option.status && (
                <Badge variant="tag">
                  {getRecipientStatusLabel(option.status)}
                </Badge>
              )}
            </MultiSelectItem>
          ))}
        </MultiSelectContent>
      </MultiSelect>
      {error && <p className="text-text-error-primary text-xs">{error}</p>}
    </div>
  );
};

export const AlertFormModal = (props: AlertFormModalProps) => {
  const resetKey = getAlertFormModalResetKey(props);

  return <AlertFormModalContent key={resetKey} {...props} />;
};

const AlertFormModalContent = ({
  open,
  defaultFrequency,
  providers = [],
  completedScanIds = [],
  scanDetails = [],
  uniqueRegions = [],
  uniqueServices = [],
  uniqueResourceTypes = [],
  uniqueCategories = [],
  uniqueGroups = [],
  editingAlert = null,
  seededCondition = null,
  selectedFindingsFilterChips = [],
  defaultName = "Findings filter alert",
  onOpenChange,
  onSubmit,
}: AlertFormModalProps) => {
  const defaults = editingAlert
    ? getAlertFormDefaults(editingAlert)
    : getEmptyAlertFormDefaults(defaultFrequency, seededCondition ?? undefined);
  const initialName = editingAlert
    ? defaults.name
    : defaults.name || defaultName;

  // Local state needed: user edits are buffered until the modal form is submitted.
  const [name, setName] = useState(initialName);
  const [description, setDescription] = useState(defaults.description);
  const [frequency, setFrequency] = useState<AlertTriggerKind>(
    defaults.frequency,
  );
  const [pendingFilters, setPendingFilters] = useState<
    Record<string, string[]>
  >(
    editingAlert
      ? getFindingsFiltersFromAlertCondition(editingAlert.attributes.condition)
      : {},
  );
  const [selectedRecipientEmails, setSelectedRecipientEmails] = useState(
    () => new Set(defaults.recipientEmails.map(normalizeEmail)),
  );
  const [errors, setErrors] = useState<FormErrors>({});
  const [saving, setSaving] = useState(false);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [preview, setPreview] = useState<PreviewState | null>(null);

  const submitLabel = editingAlert ? "Save" : "Create";

  const setRecipientEmails = (emails: string[]) =>
    setSelectedRecipientEmails(
      new Set(emails.map(normalizeEmail).filter(Boolean)),
    );

  const setPendingFilter = (filterKey: string, values: string[]) => {
    setPendingFilters((current) => ({
      ...current,
      [normalizeFindingsFilterKey(filterKey)]: uniqueValues(values),
    }));
    setPreview(null);
  };

  const getPendingFilterValue = (filterKey: string): string[] =>
    pendingFilters[normalizeFindingsFilterKey(filterKey)] ?? [];

  const buildCurrentValues = (condition: AlertCondition): AlertFormValues => ({
    name,
    description,
    method: ALERT_NOTIFICATION_METHODS.EMAIL,
    frequency,
    condition,
    recipientEmails: getRecipientEmails(selectedRecipientEmails),
    enabled: defaults.enabled,
  });

  const handlePreview = async () => {
    if (!editingAlert) return;

    const seedResult = await seedAlertRule(pendingFilters);
    if (seedResult?.error) {
      setPreview({
        status: "error",
        error: ALERT_SEED_ERROR,
      });
      return;
    }

    const values = buildCurrentValues(seedResult.data.attributes.condition);
    const parsed = alertFormSchema.safeParse(values);
    if (!parsed.success) {
      setPreview({
        status: "error",
        error: "Fix alert fields before running test.",
      });
      return;
    }

    setPreviewLoading(true);
    const result = await previewAlertCondition({
      condition: parsed.data.condition,
    });
    setPreviewLoading(false);

    if (result?.error) {
      setPreview({ status: "error", error: result.error });
      return;
    }

    const previewData = result.data.attributes as AlertPreviewResponse;
    if (previewData.evaluation_failed) {
      setPreview({
        status: "error",
        error: previewData.last_error ?? "Preview evaluation failed.",
      });
      return;
    }

    setPreview({ status: "success", data: previewData });
  };

  const handleSubmit = async () => {
    const seedResult = editingAlert
      ? await seedAlertRule(pendingFilters)
      : null;
    if (seedResult?.error) {
      setErrors({ root: ALERT_SEED_ERROR });
      return;
    }

    const values = buildCurrentValues(
      seedResult?.data.attributes.condition ?? defaults.condition,
    );
    const parsed = alertFormSchema.safeParse(values);
    if (!parsed.success) {
      const fieldErrors = parsed.error.flatten().fieldErrors;
      setErrors({
        name: fieldErrors.name?.[0],
        recipientEmails: fieldErrors.recipientEmails?.[0],
      });
      return;
    }

    setSaving(true);
    const result = await onSubmit(parsed.data);
    setSaving(false);
    if (result.ok) {
      setErrors({});
      onOpenChange(false);
      return;
    }
    setErrors({ root: result.error ?? "Could not save alert." });
  };

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={editingAlert ? "Edit Alert" : "Create Alert"}
      description={
        editingAlert
          ? "Update recipients, frequency, and finding filters for this alert."
          : "Create an alert from the current Findings filters."
      }
      onOpenAutoFocus={allowInitialDialogFocus}
      size={editingAlert ? "5xl" : "xl"}
      className={
        editingAlert
          ? "minimal-scrollbar max-h-[calc(100vh-2rem)] overflow-y-auto"
          : undefined
      }
    >
      <div className="flex flex-col gap-4">
        <FilterSummaryStrip chips={selectedFindingsFilterChips} />
        <Field>
          <FieldLabel htmlFor="alert-name">Name</FieldLabel>
          <Input
            id="alert-name"
            aria-label="Name"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          {errors.name && <FieldError>{errors.name}</FieldError>}
        </Field>
        <Field>
          <FieldLabel htmlFor="alert-description">Description</FieldLabel>
          <Textarea
            id="alert-description"
            aria-label="Description"
            textareaSize="lg"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="alert-frequency">Frequency</FieldLabel>
          <Select
            value={frequency}
            onValueChange={(value) => {
              setFrequency(value as AlertTriggerKind);
              setPreview(null);
            }}
          >
            <SelectTrigger id="alert-frequency" aria-label="Frequency">
              <SelectValue placeholder="Select frequency" />
            </SelectTrigger>
            <SelectContent width="wide" className="z-[60]">
              {ALERT_FREQUENCY_OPTIONS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <Field>
          <FieldLabel htmlFor="alert-recipients">Recipients</FieldLabel>
          <AlertRecipientsSelect
            selectedEmails={selectedRecipientEmails}
            onValuesChange={setRecipientEmails}
          />
          {errors.recipientEmails && (
            <FieldError>{errors.recipientEmails}</FieldError>
          )}
        </Field>
        {editingAlert && (
          <div className="flex flex-col gap-3">
            <Card variant="inner" padding="sm">
              <CardContent className="flex flex-col gap-3">
                <h3 className="text-text-neutral-primary text-sm font-medium">
                  Filters
                </h3>
                <FindingsFilterBatchControls
                  providers={providers}
                  completedScanIds={completedScanIds}
                  scanDetails={scanDetails}
                  uniqueRegions={uniqueRegions}
                  uniqueServices={uniqueServices}
                  uniqueResourceTypes={uniqueResourceTypes}
                  uniqueCategories={uniqueCategories}
                  uniqueGroups={uniqueGroups}
                  appliedFilters={{}}
                  pendingFilters={pendingFilters}
                  changedFilters={pendingFilters}
                  setPending={setPendingFilter}
                  getFilterValue={getPendingFilterValue}
                  showSummaries={false}
                  variant="alerts-edit"
                />
              </CardContent>
            </Card>
            {(previewLoading || preview) && (
              <div className="pt-1">
                {previewLoading ? (
                  <PreviewSummarySkeleton />
                ) : (
                  preview && <PreviewSummary preview={preview} />
                )}
              </div>
            )}
          </div>
        )}
        {errors.root && (
          <div className="text-text-error-primary text-sm">{errors.root}</div>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {editingAlert && (
            <Button
              variant="outline"
              onClick={handlePreview}
              disabled={previewLoading || saving}
            >
              {previewLoading ? "Running..." : "Test"}
            </Button>
          )}
          <Button onClick={handleSubmit} disabled={saving}>
            {submitLabel}
          </Button>
        </div>
      </div>
    </Modal>
  );
};
