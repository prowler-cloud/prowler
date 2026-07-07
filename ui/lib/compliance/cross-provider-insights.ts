import type {
  CrossProviderComplianceOverviewAttributes,
  CrossProviderRequirementStatus,
} from "@/types/compliance";

/**
 * Status a provider contributes to a single domain when its rows are
 * aggregated. ``NO_ROW`` means the universal framework does not declare
 * any check for that provider in the domain (or the scan returned no
 * rows for it) — visually rendered as dimmed so contributing-but-failing
 * providers stay distinguishable from non-contributing ones.
 */
export type DomainProviderStatus = CrossProviderRequirementStatus | "NO_ROW";

export interface ProviderCoverage {
  /** Lowercase provider key (``aws``, ``azure``, ...). */
  key: string;
  /** Whether this provider contributed at least one row. */
  contributing: boolean;
  /** Scan UUIDs associated with this provider type. A list because a
   *  tenant can have N accounts of the same type — the cross-provider
   *  endpoint aggregates one scan per Provider row. */
  scanIds: string[];
  /** PASS count across all requirements. */
  pass: number;
  /** FAIL count across all requirements. */
  fail: number;
  /** Total requirements for which the provider contributed a row. */
  total: number;
  /** ``pass / total`` rounded to integer percent (0 when total = 0). */
  scorePercent: number;
  /** Number of distinct accounts (Provider rows) of this type whose
   *  scans contribute to the aggregation. ``0`` for non-contributing
   *  providers. */
  accountCount: number;
}

export interface DomainStats {
  /** Section name (e.g. ``Audit & Assurance``). */
  name: string;
  /** Total requirements grouped under this domain. */
  total: number;
  pass: number;
  fail: number;
  manual: number;
  /** Per-provider rolled-up status across all requirements in this
   *  domain. ``FAIL`` if any req under this provider failed; ``PASS``
   *  if at least one passed and none failed; ``MANUAL`` if every
   *  contributing row is manual; ``NO_ROW`` if the provider never
   *  contributed a row to this domain. */
  byProvider: Record<string, DomainProviderStatus>;
}

export interface CrossProviderInsights {
  /** ``requirements_passed / total_requirements`` as integer percent. */
  scorePercent: number;
  pass: number;
  fail: number;
  manual: number;
  total: number;
  /** Compatible providers from the API, in display order. */
  compatibleProviders: string[];
  /** Provider keys that contributed at least one row. */
  contributingProviders: string[];
  /** Providers we actually have scans for (a subset of
   *  ``compatibleProviders`` — the ones present in ``scan_ids_by_provider``),
   *  in display order. The detail view shows only these; the overview keeps
   *  showing every compatible provider (scanned or not). */
  scannedProviders: string[];
  /** One coverage entry per SCANNED provider. (The overview lists every
   *  compatible provider and dims the unscanned ones; the detail view
   *  intentionally hides providers with no scan.) */
  providerCoverage: ProviderCoverage[];
  /** Domain stats keyed by section name, in declared order. */
  domainStats: DomainStats[];
  /** Top N domains by ``fail`` count, descending. ``N`` defaults to 3
   *  in the consumer but the helper exposes the full list. */
  domainsByFailCount: DomainStats[];
}

/**
 * Roll-up rule for a single provider's contribution to a domain (one
 * step coarser than the per-requirement roll-up the API computes).
 *
 * Mirrors the API's "FAIL > PASS > MANUAL" ordering so the domain row
 * surfaces the worst-case provider status without re-fetching anything.
 */
const aggregateDomainProviderStatuses = (
  statuses: CrossProviderRequirementStatus[],
): DomainProviderStatus => {
  if (statuses.length === 0) return "NO_ROW";
  if (statuses.some((s) => s === "FAIL")) return "FAIL";
  if (statuses.some((s) => s === "PASS")) return "PASS";
  return "MANUAL";
};

/**
 * Pull every derived figure the cross-provider header + accordion
 * components need out of a single response payload. Centralises the
 * iteration so each consumer (donut, coverage list, heatmap rows, top
 * failing teaser) runs over ``requirements`` once instead of N times.
 */
export const computeCrossProviderInsights = (
  attributes: CrossProviderComplianceOverviewAttributes,
): CrossProviderInsights => {
  const {
    compatible_providers: compatible,
    providers: contributing,
    scan_ids_by_provider: scanIdsByProvider,
    requirements,
    requirements_passed: pass,
    requirements_failed: fail,
    requirements_manual: manual,
    total_requirements: total,
  } = attributes;

  const scorePercent = total > 0 ? Math.floor((pass / total) * 100) : 0;

  const providerPass = new Map<string, number>();
  const providerFail = new Map<string, number>();
  const providerTotal = new Map<string, number>();

  // Domain accumulators are keyed by domain name. The key must match the
  // ``categoryName`` each framework's mapper derives (the accordion looks up
  // these stats by that name): CSA-CCM and CIS-Controls group by
  // ``attributes.Section``, DORA by ``attributes.Pillar``. Fall back to a
  // generic bucket so requirements without either field still surface
  // somewhere instead of silently dropping out.
  const domainAcc = new Map<
    string,
    {
      pass: number;
      fail: number;
      manual: number;
      total: number;
      perProvider: Map<string, CrossProviderRequirementStatus[]>;
    }
  >();

  for (const req of requirements) {
    const attrs = req.attributes as
      | { Section?: unknown; Pillar?: unknown }
      | undefined;
    const rawDomain = attrs?.Section ?? attrs?.Pillar;
    const section =
      typeof rawDomain === "string" && rawDomain !== "" ? rawDomain : "Other";
    let domain = domainAcc.get(section);
    if (!domain) {
      domain = {
        pass: 0,
        fail: 0,
        manual: 0,
        total: 0,
        perProvider: new Map(),
      };
      domainAcc.set(section, domain);
    }
    domain.total += 1;
    if (req.status === "PASS") domain.pass += 1;
    else if (req.status === "FAIL") domain.fail += 1;
    else domain.manual += 1;

    for (const [providerKey, status] of Object.entries(req.providers)) {
      providerTotal.set(providerKey, (providerTotal.get(providerKey) || 0) + 1);
      if (status === "PASS") {
        providerPass.set(providerKey, (providerPass.get(providerKey) || 0) + 1);
      } else if (status === "FAIL") {
        providerFail.set(providerKey, (providerFail.get(providerKey) || 0) + 1);
      }
      const list = domain.perProvider.get(providerKey) ?? [];
      list.push(status);
      domain.perProvider.set(providerKey, list);
    }
  }

  const contributingSet = new Set(contributing);

  // Providers we actually have scans for. The detail view shows only these
  // (framework-compatible providers with no scan belong on the overview,
  // where they're listed dimmed as "no scan yet"). Kept in ``compatible``
  // display order for a stable layout; a scan can only ever exist for a
  // compatible provider, so filtering ``compatible`` covers every case.
  const scannedSet = new Set(Object.keys(scanIdsByProvider ?? {}));
  const scannedProviders = compatible.filter((key) => scannedSet.has(key));

  const providerCoverage: ProviderCoverage[] = scannedProviders.map((key) => {
    const total = providerTotal.get(key) || 0;
    const pass = providerPass.get(key) || 0;
    const scorePct = total > 0 ? Math.floor((pass / total) * 100) : 0;
    const scanIds = scanIdsByProvider?.[key] ?? [];
    return {
      key,
      contributing: contributingSet.has(key),
      scanIds,
      accountCount: scanIds.length,
      pass,
      fail: providerFail.get(key) || 0,
      total,
      scorePercent: scorePct,
    };
  });

  const domainStats: DomainStats[] = Array.from(domainAcc.entries()).map(
    ([name, acc]) => {
      const byProvider: Record<string, DomainProviderStatus> = {};
      for (const providerKey of scannedProviders) {
        const statuses = acc.perProvider.get(providerKey) ?? [];
        byProvider[providerKey] = aggregateDomainProviderStatuses(statuses);
      }
      return {
        name,
        total: acc.total,
        pass: acc.pass,
        fail: acc.fail,
        manual: acc.manual,
        byProvider,
      };
    },
  );

  const domainsByFailCount = [...domainStats].sort((a, b) => b.fail - a.fail);

  return {
    scorePercent,
    pass,
    fail,
    manual,
    total,
    compatibleProviders: compatible,
    contributingProviders: contributing,
    scannedProviders,
    providerCoverage,
    domainStats,
    domainsByFailCount,
  };
};
