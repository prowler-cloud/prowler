import type {
  FindingsSeverityAttributes,
  FindingsStatusAttributes,
} from "@/actions/overview";
import type { CategoryOverviewAttributes } from "@/actions/overview/risk-radar/types";
import type {
  AiSecurityOverview,
  AiSeverityCounts,
  AiStackProvider,
  AiTopRisk,
} from "@/app/(prowler)/ai-security/_types";
import { splitCsvFilterValues } from "@/lib/findings-filters";
import type { RequirementStatus } from "@/types/compliance";
import {
  getProviderDisplayName,
  type KnownProviderType,
  type ProviderProps,
} from "@/types/providers";
import { SEVERITY_LEVELS, type SeverityLevel } from "@/types/severities";

export const AI_SECURITY_PREVIEW = {
  EMPTY: "empty",
  LOCKED: "locked",
} as const;

/** The model vendors installed from the Registry. Every check they run is an AI check. */
const MODEL_VENDORS = {
  claude: "Claude",
  openai: "OpenAI",
  chatgpt: "ChatGPT",
} as const;

/** The clouds whose AI services (Bedrock, Azure AI, Vertex AI) checks tag as gen-ai. */
const CLOUD_AI_TYPES = [
  "aws",
  "azure",
  "gcp",
] as const satisfies readonly KnownProviderType[];

type ModelVendorType = keyof typeof MODEL_VENDORS;
type CloudAiType = (typeof CLOUD_AI_TYPES)[number];

const MODEL_VENDOR_TYPES = Object.keys(MODEL_VENDORS) as ModelVendorType[];
/** The provider types the page covers. */
const AI_SPM_TYPES = [...MODEL_VENDOR_TYPES, ...CLOUD_AI_TYPES];

export const isModelVendor = (type: string): type is ModelVendorType =>
  Object.hasOwn(MODEL_VENDORS, type);

export const isCloudAi = (type: string): type is CloudAiType =>
  (CLOUD_AI_TYPES as readonly string[]).includes(type);

// Registry vendors are not in the shared display names, which would humanize "openai" to "Openai".
const providerName = (type: string) =>
  isModelVendor(type) ? MODEL_VENDORS[type] : getProviderDisplayName(type);

/** The failed checks the page lists, most severe first. */
const TOP_RISKS = 6;

/** The AI frameworks the page shows when the tenant has them installed. */
export const AI_FRAMEWORK_IDS = [
  "owasp_llm_top_10_2025",
  "owasp_agentic_top_10_2026",
  "owasp_mcp_top_10_2025",
  "nist_ai_rmf_1.0",
  "iso_42001_2023",
  "eu_ai_act_2024",
];

/** The page's scope: every AI-SPM provider type (model vendors and clouds). */
export const AI_SCOPE: Record<string, string> = {
  "filter[provider_type__in]": AI_SPM_TYPES.join(","),
};

/** The scope filters narrowed to the provider types that pass the test, or null when none does. */
export function narrowScope(
  filters: Record<string, string>,
  test: (type: string) => boolean,
): Record<string, string> | null {
  const types = splitCsvFilterValues(
    filters["filter[provider_type__in]"],
  ).filter(test);
  return types.length > 0
    ? { ...filters, "filter[provider_type__in]": types.join(",") }
    : null;
}

/**
 * The scope filters narrowed to the provider types the providers have, or null
 * when none does. Cloud answers 400 to a Registry type the tenant never installed.
 */
export const installedScope = (
  filters: Record<string, string>,
  providers: ProviderProps[],
) =>
  narrowScope(filters, (type) =>
    providers.some(({ attributes }) => attributes.provider === type),
  );

/** The tenant's AI-SPM providers, the ones the AI stack lists. */
export const aiProviders = (providers: ProviderProps[]) =>
  providers.filter(
    ({ attributes }) =>
      isModelVendor(attributes.provider) || isCloudAi(attributes.provider),
  );

export interface AiFindingGroup {
  id: string;
  attributes: {
    check_title: string | null;
    status: RequirementStatus;
    severity: string;
    impacted_providers: string[];
    resources_fail: number;
    new_fail_count: number;
    changed_fail_count: number;
    fail_count: number;
    last_seen_at: string | null;
  };
}

export interface AiOverviewSources {
  /** The AI-SPM providers the stack lists. */
  providers: ProviderProps[];
  /** The latest scans' results of each model vendor type the stack lists. */
  results: Partial<Record<string, FindingsStatusAttributes>>;
  /** The latest scans' gen-ai findings of each cloud type the stack lists. */
  cloudResults: Partial<Record<string, CategoryOverviewAttributes>>;
  /** The provider types with a completed scan among the providers listed. */
  scannedTypes: string[];
  /** The failed findings by severity of each model vendor type the stack lists. */
  severities: Partial<Record<string, FindingsSeverityAttributes>>;
  /** Failed checks of the model vendors and of the clouds' gen-ai, in any order. */
  findingGroups: AiFindingGroup[];
}

const plural = (count: number, word: string) =>
  `${count.toLocaleString()} ${word}${count === 1 ? "" : "s"}`;

const isSeverityLevel = (value: string): value is SeverityLevel =>
  (SEVERITY_LEVELS as readonly string[]).includes(value);

const severityRank = (severity: string) =>
  (SEVERITY_LEVELS as readonly string[]).indexOf(severity);

const toTopRisk = ({ id, attributes }: AiFindingGroup): AiTopRisk | null =>
  isSeverityLevel(attributes.severity)
    ? {
        checkId: id,
        title: attributes.check_title ?? id,
        severity: attributes.severity,
        providerName: attributes.impacted_providers
          .map(providerName)
          .join(", "),
        affected: plural(attributes.resources_fail, "resource"),
      }
    : null;

const NO_SEVERITY: AiSeverityCounts = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  informational: 0,
};

/**
 * The services with failed checks of a provider type, from the check ids:
 * the SDK requires every check id to start with its service name.
 */
const servicesOf = (findingGroups: AiFindingGroup[], type: string) =>
  Array.from(
    new Set(
      findingGroups
        .filter(({ attributes }) =>
          attributes.impacted_providers.includes(type),
        )
        .map(({ id }) => id.split("_")[0]),
    ),
  ).sort();

const accountsOf = (providers: ProviderProps[], type: string) =>
  providers.filter((provider) => provider.attributes.provider === type).length;

/** Maps the overview, compliance and finding-group responses to what the widgets show. */
export function toAiSecurityOverview({
  providers,
  results,
  cloudResults,
  scannedTypes,
  severities,
  findingGroups,
}: AiOverviewSources): AiSecurityOverview {
  const vendors: AiStackProvider[] = MODEL_VENDOR_TYPES.map((type) => {
    const accounts = accountsOf(providers, type);
    const result = results[type];
    const pass = result?.pass ?? 0;
    const fail = result?.fail ?? 0;
    // Overview totals count every status; what is neither pass, fail nor muted is manual.
    const manual = result
      ? Math.max(result.total - pass - fail - result.muted, 0)
      : 0;
    return {
      type,
      name: MODEL_VENDORS[type],
      scope: plural(accounts, "account"),
      connected: accounts > 0,
      scanned: scannedTypes.includes(type),
      pass,
      fail,
      manual,
      newFail: result?.fail_new ?? 0,
      severity: severities[type] ?? NO_SEVERITY,
      services: servicesOf(findingGroups, type),
    };
  });

  const clouds: AiStackProvider[] = CLOUD_AI_TYPES.map((type) => {
    const accounts = accountsOf(providers, type);
    const result = cloudResults[type];
    const fail = result?.failed_findings ?? 0;
    return {
      type,
      name: getProviderDisplayName(type),
      scope: plural(accounts, "account"),
      connected: accounts > 0,
      scanned: scannedTypes.includes(type),
      // shortcut: the category totals have no manual count, so a manual gen-ai finding counts as pass; split it out if a cloud gen-ai check turns manual.
      pass: Math.max((result?.total_findings ?? 0) - fail, 0),
      fail,
      manual: 0,
      newFail: result?.new_failed_findings ?? 0,
      severity: result?.severity ?? NO_SEVERITY,
      services: servicesOf(findingGroups, type),
    };
  });

  const rows = [...vendors, ...clouds];

  return {
    pass: rows.reduce((sum, row) => sum + row.pass, 0),
    fail: rows.reduce((sum, row) => sum + row.fail, 0),
    manual: rows.reduce((sum, row) => sum + row.manual, 0),
    newFail: rows.reduce((sum, row) => sum + row.newFail, 0),
    severity: Object.fromEntries(
      SEVERITY_LEVELS.map((level) => [
        level,
        rows.reduce((sum, row) => sum + row.severity[level], 0),
      ]),
    ) as AiSeverityCounts,
    layers: [
      {
        id: "model-vendors",
        name: "Model vendors",
        description:
          "Organization settings, API keys, projects and connectors in the vendor accounts.",
        providers: vendors,
      },
      {
        id: "cloud-ai-services",
        name: "Cloud AI services",
        description:
          "Bedrock and AgentCore, Azure AI services and OpenAI, Vertex AI: the gen-ai checks of your cloud accounts.",
        providers: clouds,
      },
    ],
    topRisks: [...findingGroups]
      .sort(
        (a, b) =>
          severityRank(a.attributes.severity) -
            severityRank(b.attributes.severity) ||
          b.attributes.new_fail_count - a.attributes.new_fail_count ||
          b.attributes.changed_fail_count - a.attributes.changed_fail_count ||
          b.attributes.fail_count - a.attributes.fail_count ||
          (b.attributes.last_seen_at ?? "").localeCompare(
            a.attributes.last_seen_at ?? "",
          ),
      )
      .map(toTopRisk)
      .filter((risk): risk is AiTopRisk => risk !== null)
      .slice(0, TOP_RISKS),
  };
}
