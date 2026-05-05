import type { AlertPayload } from "@/app/(prowler)/alerts/_actions/alerts";
import {
  ALERT_AGGREGATE_OPS,
  ALERT_BOOLEAN_OPS,
  ALERT_DELTA_VALUES,
  ALERT_SEVERITY_VALUES,
  ALERT_TRIGGER_KINDS,
  type AlertCondition,
  type AlertDelta,
  type AlertLeafFilter,
  type AlertProviderType,
  type AlertRule,
  type AlertSeverity,
} from "@/app/(prowler)/alerts/_types";

import {
  ALERT_FILTER_FIELDS,
  ALERT_FILTER_OPERATORS,
  ALERT_NOTIFICATION_METHODS,
  type AlertFormDefaults,
  type AlertFormFilterGroup,
  type AlertFormFilterItem,
  type AlertFormFilterNode,
  type AlertFormFindingFilterBag,
  type AlertFormValues,
} from "../_types/alert-form";

const DEFAULT_SEVERITIES: AlertSeverity[] = [...ALERT_SEVERITY_VALUES];

const normalizeStringValues = (values: string[]): string[] =>
  values.map((value) => value.trim()).filter(Boolean);

const createFilterNode = (
  field: AlertFormFilterItem["field"],
  values: string[],
): AlertFormFilterItem => ({ kind: "filter", field, values });

const getStringArrayFilterValue = (
  filter: AlertLeafFilter,
  field: keyof AlertLeafFilter,
): string[] => {
  const value = filter[field];
  return Array.isArray(value) ? value : [];
};

const normalizeRecipientEmails = (emails: string[]): string[] =>
  emails
    .map((email) => email.trim().toLowerCase())
    .filter((email) => email.length > 0);

const filterItemToLeafFilter = (
  item: AlertFormFilterItem,
): AlertLeafFilter | null => {
  const normalized = normalizeStringValues(item.values);
  if (normalized.length === 0) return null;

  switch (item.field) {
    case ALERT_FILTER_FIELDS.PROVIDERS:
      return { provider_type: normalized as AlertProviderType[] };
    case ALERT_FILTER_FIELDS.ACCOUNTS:
      return { provider_id: normalized };
    case ALERT_FILTER_FIELDS.CHECK_SEVERITIES:
      return { severity: normalized as AlertSeverity[] };
    case ALERT_FILTER_FIELDS.RESOURCES:
      return { resource_uid: normalized };
    case ALERT_FILTER_FIELDS.RESOURCE_TYPES:
      return { resource_types: normalized };
    case ALERT_FILTER_FIELDS.REGIONS:
      return { resource_regions: normalized };
    case ALERT_FILTER_FIELDS.SERVICES:
      return { resource_services: normalized };
    case ALERT_FILTER_FIELDS.CATEGORIES:
      return { categories: normalized };
    case ALERT_FILTER_FIELDS.RESOURCE_GROUPS:
      return { resource_groups: normalized };
    case ALERT_FILTER_FIELDS.TYPE: {
      const deltas = normalized.filter((value) =>
        ALERT_DELTA_VALUES.includes(value as AlertDelta),
      ) as AlertDelta[];
      return deltas.length > 0 ? { delta: deltas } : null;
    }
    case ALERT_FILTER_FIELDS.CHECKS:
      return { check_id: normalized };
    case ALERT_FILTER_FIELDS.CHECK_STATUSES:
    case ALERT_FILTER_FIELDS.ACCOUNT_TAGS:
    case ALERT_FILTER_FIELDS.DATA_DATE_WINDOW:
    case ALERT_FILTER_FIELDS.INCLUDE_MUTED_FINDINGS:
      return null;
  }
};

const buildConditionFromNode = (
  node: AlertFormFilterNode,
): AlertCondition | null => {
  if (node.kind === "filter") {
    const filter = filterItemToLeafFilter(node);
    return filter
      ? { op: ALERT_AGGREGATE_OPS.COUNT_GTE, filter, value: 1 }
      : null;
  }

  return buildConditionFromGroup(node);
};

const buildConditionFromGroup = (
  group: AlertFormFilterGroup,
): AlertCondition => {
  const children = group.children
    .map(buildConditionFromNode)
    .filter((condition): condition is AlertCondition => condition !== null);

  if (children.length === 0) {
    return {
      op: ALERT_AGGREGATE_OPS.COUNT_GTE,
      filter: { severity: DEFAULT_SEVERITIES },
      value: 1,
    };
  }

  if (children.length === 1) return children[0];

  return group.operator === ALERT_FILTER_OPERATORS.ANY
    ? { op: ALERT_BOOLEAN_OPS.OR, children }
    : { op: ALERT_BOOLEAN_OPS.AND, children };
};

const legacyValuesToFilterGroup = (
  values: Partial<AlertFormValues>,
): AlertFormFilterGroup => ({
  operator: ALERT_FILTER_OPERATORS.ALL,
  children: [
    createFilterNode(
      ALERT_FILTER_FIELDS.CHECK_SEVERITIES,
      values.severities ?? DEFAULT_SEVERITIES,
    ),
    createFilterNode(ALERT_FILTER_FIELDS.TYPE, values.deltas ?? []),
    createFilterNode(ALERT_FILTER_FIELDS.PROVIDERS, values.providerTypes ?? []),
    createFilterNode(ALERT_FILTER_FIELDS.ACCOUNTS, values.providerIds ?? []),
    createFilterNode(ALERT_FILTER_FIELDS.CHECKS, values.checkIds ?? []),
    createFilterNode(
      ALERT_FILTER_FIELDS.RESOURCE_TYPES,
      values.resourceTypes ?? [],
    ),
    createFilterNode(ALERT_FILTER_FIELDS.REGIONS, values.regions ?? []),
    createFilterNode(ALERT_FILTER_FIELDS.SERVICES, values.services ?? []),
    createFilterNode(ALERT_FILTER_FIELDS.CATEGORIES, values.categories ?? []),
    createFilterNode(
      ALERT_FILTER_FIELDS.RESOURCE_GROUPS,
      values.resourceGroups ?? [],
    ),
    createFilterNode(ALERT_FILTER_FIELDS.RESOURCES, []),
  ],
});

const isAlertFormFilterGroup = (
  values: AlertFormFilterGroup | Partial<AlertFormValues>,
): values is AlertFormFilterGroup =>
  "children" in values && "operator" in values;

export const buildAlertCondition = (
  values: AlertFormFilterGroup | Partial<AlertFormValues>,
): AlertCondition => {
  const group = isAlertFormFilterGroup(values)
    ? values
    : (values.filterGroup ?? legacyValuesToFilterGroup(values));
  return buildConditionFromGroup(group);
};

const ALERT_FILTER_FIELDS_ALLOWED = new Set<keyof AlertLeafFilter>([
  "severity",
  "delta",
  "provider_type",
  "provider_id",
  "check_id",
  "resource_regions",
  "resource_services",
  "resource_types",
  "categories",
  "resource_groups",
  "resource_uid",
]);

const isAlertFormFilter = (condition: AlertCondition): boolean => {
  if (
    condition.op !== ALERT_AGGREGATE_OPS.ANY &&
    condition.op !== ALERT_AGGREGATE_OPS.COUNT_GTE
  ) {
    return false;
  }
  if (condition.op === ALERT_AGGREGATE_OPS.COUNT_GTE && condition.value !== 1) {
    return false;
  }
  return Object.keys(condition.filter).every((field) =>
    ALERT_FILTER_FIELDS_ALLOWED.has(field as keyof AlertLeafFilter),
  );
};

const mergeLeafFilters = (filters: AlertLeafFilter[]): AlertLeafFilter => {
  const merged: AlertLeafFilter = {};

  filters.forEach((filter) => {
    Object.entries(filter).forEach(([field, value]) => {
      if (!Array.isArray(value)) return;
      const key = field as keyof AlertLeafFilter;
      const current = Array.isArray(merged[key]) ? merged[key] : [];
      merged[key] = Array.from(new Set([...current, ...value]));
    });
  });

  return merged;
};

const getSimpleFilterFromCondition = (
  condition: AlertCondition,
): AlertLeafFilter | null => {
  if (
    isAlertFormFilter(condition) &&
    (condition.op === ALERT_AGGREGATE_OPS.ANY ||
      condition.op === ALERT_AGGREGATE_OPS.COUNT_GTE)
  ) {
    return condition.filter;
  }

  if (condition.op !== ALERT_BOOLEAN_OPS.AND) return null;

  const childFilters = condition.children.map((child) =>
    isAlertFormFilter(child) &&
    (child.op === ALERT_AGGREGATE_OPS.ANY ||
      child.op === ALERT_AGGREGATE_OPS.COUNT_GTE)
      ? child.filter
      : null,
  );

  if (childFilters.some((filter) => filter === null)) return null;

  return mergeLeafFilters(childFilters as AlertLeafFilter[]);
};

const pickAlertFormFilterFields = (
  filter: AlertLeafFilter,
): AlertLeafFilter | null => {
  const simpleFilter: AlertLeafFilter = {};

  Object.entries(filter).forEach(([field, value]) => {
    if (
      !ALERT_FILTER_FIELDS_ALLOWED.has(field as keyof AlertLeafFilter) ||
      !Array.isArray(value) ||
      value.length === 0
    ) {
      return;
    }

    simpleFilter[field as keyof AlertLeafFilter] = value;
  });

  return Object.keys(simpleFilter).length > 0 ? simpleFilter : null;
};

const getPortableFiltersFromCondition = (
  condition: AlertCondition,
): AlertLeafFilter[] => {
  if ("filter" in condition) {
    const simpleFilter = pickAlertFormFilterFields(condition.filter);
    return simpleFilter ? [simpleFilter] : [];
  }

  if ("child" in condition) {
    return getPortableFiltersFromCondition(condition.child);
  }

  return condition.children.flatMap(getPortableFiltersFromCondition);
};

const getEditableFilterFromCondition = (
  condition: AlertCondition,
): AlertLeafFilter | null =>
  getSimpleFilterFromCondition(condition) ??
  (() => {
    const portableFilters = getPortableFiltersFromCondition(condition);
    return portableFilters.length > 0
      ? mergeLeafFilters(portableFilters)
      : null;
  })();

const filterToSimpleGroup = (
  filter: AlertLeafFilter,
): AlertFormFilterGroup => ({
  operator: ALERT_FILTER_OPERATORS.ALL,
  children: [
    createFilterNode(
      ALERT_FILTER_FIELDS.CHECK_SEVERITIES,
      getStringArrayFilterValue(filter, "severity"),
    ),
    createFilterNode(
      ALERT_FILTER_FIELDS.TYPE,
      getStringArrayFilterValue(filter, "delta"),
    ),
    createFilterNode(
      ALERT_FILTER_FIELDS.PROVIDERS,
      getStringArrayFilterValue(filter, "provider_type"),
    ),
    createFilterNode(
      ALERT_FILTER_FIELDS.ACCOUNTS,
      getStringArrayFilterValue(filter, "provider_id"),
    ),
    createFilterNode(
      ALERT_FILTER_FIELDS.CHECKS,
      getStringArrayFilterValue(filter, "check_id"),
    ),
    createFilterNode(
      ALERT_FILTER_FIELDS.REGIONS,
      getStringArrayFilterValue(filter, "resource_regions"),
    ),
    createFilterNode(
      ALERT_FILTER_FIELDS.SERVICES,
      getStringArrayFilterValue(filter, "resource_services"),
    ),
    createFilterNode(
      ALERT_FILTER_FIELDS.CATEGORIES,
      getStringArrayFilterValue(filter, "categories"),
    ),
    createFilterNode(
      ALERT_FILTER_FIELDS.RESOURCE_GROUPS,
      getStringArrayFilterValue(filter, "resource_groups"),
    ),
    createFilterNode(
      ALERT_FILTER_FIELDS.RESOURCES,
      getStringArrayFilterValue(filter, "resource_uid"),
    ),
    createFilterNode(
      ALERT_FILTER_FIELDS.RESOURCE_TYPES,
      getStringArrayFilterValue(filter, "resource_types"),
    ),
  ].filter((node) => node.values.length > 0),
});

export const toAlertPayload = (
  values: AlertFormValues,
  _existingCondition?: AlertCondition | null,
): AlertPayload => ({
  name: values.name.trim(),
  description: values.description.trim(),
  enabled: values.enabled,
  trigger: values.frequency,
  condition: buildAlertCondition(values.filterGroup),
  recipientEmails: normalizeRecipientEmails(values.recipientEmails),
});

export const getEmptyAlertFormDefaults = (
  frequency: AlertFormValues["frequency"] = ALERT_TRIGGER_KINDS.AFTER_SCAN,
): AlertFormDefaults => ({
  name: "",
  description: "",
  method: ALERT_NOTIFICATION_METHODS.EMAIL,
  frequency,
  filterGroup: {
    operator: ALERT_FILTER_OPERATORS.ALL,
    children: [
      createFilterNode(
        ALERT_FILTER_FIELDS.CHECK_SEVERITIES,
        DEFAULT_SEVERITIES,
      ),
    ],
  },
  severities: DEFAULT_SEVERITIES,
  deltas: [],
  providerTypes: [],
  providerIds: [],
  checkIds: [],
  categories: [],
  regions: [],
  services: [],
  resourceGroups: [],
  resourceTypes: [],
  recipientEmails: [],
  enabled: true,
  advancedCondition: null,
});

export const getAlertFormDefaults = (alert: AlertRule): AlertFormDefaults => {
  const simpleFilter = getEditableFilterFromCondition(
    alert.attributes.condition,
  );
  const simpleSeverities = Array.isArray(simpleFilter?.severity)
    ? (simpleFilter.severity as AlertSeverity[])
    : null;

  return {
    name: alert.attributes.name,
    description: alert.attributes.description,
    method: ALERT_NOTIFICATION_METHODS.EMAIL,
    frequency: alert.attributes.trigger,
    filterGroup: simpleFilter
      ? filterToSimpleGroup(simpleFilter)
      : getEmptyAlertFormDefaults(alert.attributes.trigger).filterGroup,
    severities: simpleSeverities ?? DEFAULT_SEVERITIES,
    deltas: (simpleFilter?.delta ?? []) as AlertDelta[],
    providerTypes: (simpleFilter?.provider_type ?? []) as AlertProviderType[],
    providerIds: getStringArrayFilterValue(simpleFilter ?? {}, "provider_id"),
    checkIds: getStringArrayFilterValue(simpleFilter ?? {}, "check_id"),
    categories: getStringArrayFilterValue(simpleFilter ?? {}, "categories"),
    regions: getStringArrayFilterValue(simpleFilter ?? {}, "resource_regions"),
    services: getStringArrayFilterValue(
      simpleFilter ?? {},
      "resource_services",
    ),
    resourceGroups: getStringArrayFilterValue(
      simpleFilter ?? {},
      "resource_groups",
    ),
    resourceTypes: getStringArrayFilterValue(
      simpleFilter ?? {},
      "resource_types",
    ),
    recipientEmails: alert.attributes.recipient_emails ?? [],
    enabled: alert.attributes.enabled,
    advancedCondition: null,
  };
};

const FINDINGS_FILTER_KEY_TO_SIMPLE_FIELD: Record<
  string,
  AlertFormFilterItem["field"]
> = {
  provider_type: ALERT_FILTER_FIELDS.PROVIDERS,
  provider_type__in: ALERT_FILTER_FIELDS.PROVIDERS,
  "provider_type.in": ALERT_FILTER_FIELDS.PROVIDERS,
  provider_id: ALERT_FILTER_FIELDS.ACCOUNTS,
  provider_id__in: ALERT_FILTER_FIELDS.ACCOUNTS,
  "provider_id.in": ALERT_FILTER_FIELDS.ACCOUNTS,
  severity: ALERT_FILTER_FIELDS.CHECK_SEVERITIES,
  severity__in: ALERT_FILTER_FIELDS.CHECK_SEVERITIES,
  "severity.in": ALERT_FILTER_FIELDS.CHECK_SEVERITIES,
  delta: ALERT_FILTER_FIELDS.TYPE,
  delta__in: ALERT_FILTER_FIELDS.TYPE,
  "delta.in": ALERT_FILTER_FIELDS.TYPE,
  region: ALERT_FILTER_FIELDS.REGIONS,
  region__in: ALERT_FILTER_FIELDS.REGIONS,
  resource_regions: ALERT_FILTER_FIELDS.REGIONS,
  resource_regions__in: ALERT_FILTER_FIELDS.REGIONS,
  "resource_regions.in": ALERT_FILTER_FIELDS.REGIONS,
  service: ALERT_FILTER_FIELDS.SERVICES,
  service__in: ALERT_FILTER_FIELDS.SERVICES,
  resource_services: ALERT_FILTER_FIELDS.SERVICES,
  resource_services__in: ALERT_FILTER_FIELDS.SERVICES,
  "resource_services.in": ALERT_FILTER_FIELDS.SERVICES,
  category: ALERT_FILTER_FIELDS.CATEGORIES,
  category__in: ALERT_FILTER_FIELDS.CATEGORIES,
  categories: ALERT_FILTER_FIELDS.CATEGORIES,
  categories__in: ALERT_FILTER_FIELDS.CATEGORIES,
  "categories.in": ALERT_FILTER_FIELDS.CATEGORIES,
  resource_groups: ALERT_FILTER_FIELDS.RESOURCE_GROUPS,
  resource_groups__in: ALERT_FILTER_FIELDS.RESOURCE_GROUPS,
  "resource_groups.in": ALERT_FILTER_FIELDS.RESOURCE_GROUPS,
  check_id: ALERT_FILTER_FIELDS.CHECKS,
  check_id__in: ALERT_FILTER_FIELDS.CHECKS,
  "check_id.in": ALERT_FILTER_FIELDS.CHECKS,
  resource_uid: ALERT_FILTER_FIELDS.RESOURCES,
  resource_uid__in: ALERT_FILTER_FIELDS.RESOURCES,
  "resource_uid.in": ALERT_FILTER_FIELDS.RESOURCES,
  resource_type: ALERT_FILTER_FIELDS.RESOURCE_TYPES,
  resource_type__in: ALERT_FILTER_FIELDS.RESOURCE_TYPES,
  resource_types: ALERT_FILTER_FIELDS.RESOURCE_TYPES,
  resource_types__in: ALERT_FILTER_FIELDS.RESOURCE_TYPES,
  "resource_types.in": ALERT_FILTER_FIELDS.RESOURCE_TYPES,
};

const unwrapFindingsFilterKey = (rawKey: string): string => {
  if (rawKey.startsWith("filter[") && rawKey.endsWith("]")) {
    return rawKey.slice("filter[".length, -1);
  }

  return rawKey;
};

const splitFindingsFilterValues = (
  value: AlertFormFindingFilterBag[string],
): string[] => {
  const values = Array.isArray(value) ? value : [value];
  return normalizeStringValues(
    values.flatMap((entry) => String(entry).split(",")),
  );
};

const getFieldValuesFromFindingsFilters = (
  filterBag: AlertFormFindingFilterBag,
): Partial<Record<AlertFormFilterItem["field"], string[]>> => {
  const fieldValues: Partial<Record<AlertFormFilterItem["field"], string[]>> =
    {};

  Object.entries(filterBag).forEach(([rawKey, rawValue]) => {
    const field =
      FINDINGS_FILTER_KEY_TO_SIMPLE_FIELD[unwrapFindingsFilterKey(rawKey)];
    if (!field) return;
    const values = splitFindingsFilterValues(rawValue);
    if (values.length === 0) return;
    fieldValues[field] = [...(fieldValues[field] ?? []), ...values];
  });

  return fieldValues;
};

const FINDINGS_FILTER_FIELD_ORDER = [
  ALERT_FILTER_FIELDS.PROVIDERS,
  ALERT_FILTER_FIELDS.ACCOUNTS,
  ALERT_FILTER_FIELDS.CHECK_SEVERITIES,
  ALERT_FILTER_FIELDS.TYPE,
  ALERT_FILTER_FIELDS.REGIONS,
  ALERT_FILTER_FIELDS.SERVICES,
  ALERT_FILTER_FIELDS.CATEGORIES,
  ALERT_FILTER_FIELDS.RESOURCE_GROUPS,
  ALERT_FILTER_FIELDS.CHECKS,
  ALERT_FILTER_FIELDS.RESOURCE_TYPES,
  ALERT_FILTER_FIELDS.RESOURCES,
] as const;

export const getAlertFormDefaultsFromFindingsFilters = (
  filterBag: AlertFormFindingFilterBag,
  frequency: AlertFormValues["frequency"] = ALERT_TRIGGER_KINDS.AFTER_SCAN,
): AlertFormDefaults => {
  const fieldValues = getFieldValuesFromFindingsFilters(filterBag);
  const children = FINDINGS_FILTER_FIELD_ORDER.flatMap((field) => {
    const values = fieldValues[field] ?? [];
    return values.length > 0 ? [createFilterNode(field, values)] : [];
  });
  const defaults = getEmptyAlertFormDefaults(frequency);

  return {
    ...defaults,
    filterGroup: {
      operator: ALERT_FILTER_OPERATORS.ALL,
      children: children.length > 0 ? children : defaults.filterGroup.children,
    },
    severities: (fieldValues[ALERT_FILTER_FIELDS.CHECK_SEVERITIES] ??
      defaults.severities) as AlertFormValues["severities"],
    deltas: (fieldValues[ALERT_FILTER_FIELDS.TYPE] ??
      defaults.deltas) as AlertFormValues["deltas"],
    providerTypes: (fieldValues[ALERT_FILTER_FIELDS.PROVIDERS] ??
      defaults.providerTypes) as AlertFormValues["providerTypes"],
    providerIds:
      fieldValues[ALERT_FILTER_FIELDS.ACCOUNTS] ?? defaults.providerIds,
    checkIds: fieldValues[ALERT_FILTER_FIELDS.CHECKS] ?? defaults.checkIds,
    regions: fieldValues[ALERT_FILTER_FIELDS.REGIONS] ?? defaults.regions,
    categories:
      fieldValues[ALERT_FILTER_FIELDS.CATEGORIES] ?? defaults.categories,
    services: fieldValues[ALERT_FILTER_FIELDS.SERVICES] ?? defaults.services,
    resourceGroups:
      fieldValues[ALERT_FILTER_FIELDS.RESOURCE_GROUPS] ??
      defaults.resourceGroups,
    resourceTypes:
      fieldValues[ALERT_FILTER_FIELDS.RESOURCE_TYPES] ?? defaults.resourceTypes,
  };
};
