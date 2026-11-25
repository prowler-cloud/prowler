import type {
  FindingsSeverityAttributes,
  FindingsStatusAttributes,
} from "@/actions/overview";
import type { CategoryOverviewAttributes } from "@/actions/overview/risk-radar/types";
import type {
  AiFramework,
  AiSecurityOverview,
  AiStackProvider,
  AiTopRisk,
} from "@/app/(prowler)/ai-security/_types";
import { splitCsvFilterValues } from "@/lib/findings-filters";
import type { SearchParamsProps } from "@/types";
import type {
  ComplianceOverviewData,
  RequirementStatus,
} from "@/types/compliance";
import type { ProviderProps } from "@/types/providers";
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
const CLOUD_AI_SERVICES = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
} as const;

type ModelVendorType = keyof typeof MODEL_VENDORS;
type CloudAiType = keyof typeof CLOUD_AI_SERVICES;

const MODEL_VENDOR_TYPES = Object.keys(MODEL_VENDORS) as ModelVendorType[];
const CLOUD_AI_TYPES = Object.keys(CLOUD_AI_SERVICES) as CloudAiType[];
/** The provider types the page covers. */
const AI_SPM_TYPES = [...MODEL_VENDOR_TYPES, ...CLOUD_AI_TYPES];

const PROVIDER_NAMES: Record<string, string> = {
  ...MODEL_VENDORS,
  ...CLOUD_AI_SERVICES,
};

export const isModelVendor = (type: string): type is ModelVendorType =>
  Object.hasOwn(MODEL_VENDORS, type);

export const isCloudAi = (type: string): type is CloudAiType =>
  Object.hasOwn(CLOUD_AI_SERVICES, type);

/** The failed checks the page lists, most severe first. */
export const TOP_RISKS = 6;

type AiFrameworkInfo = Pick<AiFramework, "shortName" | "name" | "unit">;

/** The AI frameworks the page shows when the tenant has them installed, keyed by compliance id. */
export const AI_FRAMEWORKS: Record<string, AiFrameworkInfo> = {
  owasp_llm_top_10_2025: {
    shortName: "OWASP LLM Top 10",
    name: "OWASP Top 10 for LLM Applications",
    unit: "requirements",
  },
  owasp_agentic_top_10_2026: {
    shortName: "OWASP Agentic Top 10",
    name: "OWASP Top 10 for Agentic Applications",
    unit: "requirements",
  },
  owasp_mcp_top_10_2025: {
    shortName: "OWASP MCP Top 10",
    name: "OWASP MCP Top 10",
    unit: "requirements",
  },
  "nist_ai_rmf_1.0": {
    shortName: "NIST AI RMF",
    name: "NIST AI Risk Management Framework",
    unit: "subcategories",
  },
  iso_42001_2023: {
    shortName: "ISO/IEC 42001",
    name: "ISO/IEC 42001 Annex A controls",
    unit: "controls",
  },
  eu_ai_act_2024: {
    shortName: "EU AI Act",
    name: "EU AI Act, deployer obligations",
    unit: "requirements",
  },
};

const SCOPE_KEYS = [
  "filter[provider_id__in]",
  "filter[provider_groups__in]",
] as const;

/**
 * The page's provider filters narrowed to the AI-SPM provider types (model
 * vendors and clouds), or null when the selected types leave none of them.
 */
export function aiScopeFilters(
  searchParams: SearchParamsProps,
): Record<string, string> | null {
  const selected = splitCsvFilterValues(
    searchParams["filter[provider_type__in]"],
  );
  const types = AI_SPM_TYPES.filter(
    (type) => selected.length === 0 || selected.includes(type),
  );
  if (types.length === 0) return null;

  const filters: Record<string, string> = {
    "filter[provider_type__in]": types.join(","),
  };
  for (const key of SCOPE_KEYS) {
    const value = splitCsvFilterValues(searchParams[key]).join(",");
    if (value) filters[key] = value;
  }
  return filters;
}

/** The scope filters narrowed to the provider types that pass the test, or null when none does. */
export function narrowScope(
  filters: Record<string, string>,
  test: (type: string) => boolean,
): Record<string, string> | null {
  const types = filters["filter[provider_type__in]"].split(",").filter(test);
  return types.length > 0
    ? { ...filters, "filter[provider_type__in]": types.join(",") }
    : null;
}

/**
 * The AI-SPM providers of every type the account filter allows. The AI stack
 * lists them all, so a row can switch the page to another provider type.
 */
export function aiProvidersInScope(
  providers: ProviderProps[],
  filters: Record<string, string>,
) {
  const ids = filters["filter[provider_id__in]"]?.split(",");
  return providers.filter(
    (provider) =>
      Object.hasOwn(PROVIDER_NAMES, provider.attributes.provider) &&
      (!ids || ids.includes(provider.id)),
  );
}

export interface AiFindingGroup {
  id: string;
  attributes: {
    check_title: string | null;
    status: RequirementStatus;
    severity: string;
    impacted_providers: string[];
    resources_fail: number;
  };
}

export interface AiOverviewSources {
  /** The AI-SPM providers the stack lists. */
  providers: ProviderProps[];
  /** The provider types the page is filtered to; the totals count only these. */
  types: string[];
  /** The latest scans' results of each model vendor type the stack lists. */
  results: Partial<Record<string, FindingsStatusAttributes>>;
  /** The latest scans' gen-ai findings of each cloud type the stack lists. */
  cloudResults: Partial<Record<string, CategoryOverviewAttributes>>;
  /** The model vendors' failed findings by severity. */
  severity: FindingsSeverityAttributes;
  frameworks: ComplianceOverviewData[];
  /** Failed checks of the model vendors and of the clouds' gen-ai, in any order. */
  findingGroups: AiFindingGroup[];
}

const plural = (count: number, word: string) =>
  `${count.toLocaleString()} ${word}${count === 1 ? "" : "s"}`;

const isSeverityLevel = (value: string): value is SeverityLevel =>
  (SEVERITY_LEVELS as readonly string[]).includes(value);

const providerName = (type: string) => PROVIDER_NAMES[type] ?? type;

const severityRank = (severity: string) =>
  (SEVERITY_LEVELS as readonly string[]).indexOf(severity);

const toFramework = ({
  id,
  attributes,
}: ComplianceOverviewData): AiFramework => ({
  id,
  title: attributes.framework,
  version: attributes.version,
  ...AI_FRAMEWORKS[id],
  pass: attributes.requirements_passed,
  fail: attributes.requirements_failed,
  manual: attributes.requirements_manual,
});

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

const accountsOf = (providers: ProviderProps[], type: string) =>
  providers.filter((provider) => provider.attributes.provider === type).length;

/** Maps the overview, compliance and finding-group responses to what the widgets show. */
export function toAiSecurityOverview({
  providers,
  types,
  results,
  cloudResults,
  severity,
  frameworks,
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
      pass,
      fail,
      manual,
    };
  });

  const clouds: AiStackProvider[] = CLOUD_AI_TYPES.map((type) => {
    const accounts = accountsOf(providers, type);
    const result = cloudResults[type];
    const fail = result?.failed_findings ?? 0;
    return {
      type,
      name: CLOUD_AI_SERVICES[type],
      scope: plural(accounts, "account"),
      connected: accounts > 0,
      // shortcut: the category totals have no manual count, so a manual gen-ai finding counts as pass; split it out if a cloud gen-ai check turns manual.
      pass: Math.max((result?.total_findings ?? 0) - fail, 0),
      fail,
      manual: 0,
    };
  });

  const inScope = [...vendors, ...clouds].filter((row) =>
    types.includes(row.type),
  );
  const cloudSeverity = CLOUD_AI_TYPES.filter((type) => types.includes(type))
    .map((type) => cloudResults[type]?.severity)
    .filter((counts) => counts !== undefined);

  return {
    pass: inScope.reduce((sum, row) => sum + row.pass, 0),
    fail: inScope.reduce((sum, row) => sum + row.fail, 0),
    manual: inScope.reduce((sum, row) => sum + row.manual, 0),
    severity: Object.fromEntries(
      SEVERITY_LEVELS.map((level) => [
        level,
        cloudSeverity.reduce(
          (sum, counts) => sum + counts[level],
          severity[level],
        ),
      ]),
    ) as AiSecurityOverview["severity"],
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
    frameworks: frameworks
      .filter(({ id }) => Object.hasOwn(AI_FRAMEWORKS, id))
      .map(toFramework),
    topRisks: [...findingGroups]
      .sort(
        (a, b) =>
          severityRank(a.attributes.severity) -
            severityRank(b.attributes.severity) ||
          b.attributes.resources_fail - a.attributes.resources_fail,
      )
      .map(toTopRisk)
      .filter((risk): risk is AiTopRisk => risk !== null)
      .slice(0, TOP_RISKS),
  };
}
