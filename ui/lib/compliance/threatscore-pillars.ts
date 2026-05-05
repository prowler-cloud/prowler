import type { SectionScores } from "@/actions/overview/threat-score";

export const THREATSCORE_PILLARS = [
  "1. IAM",
  "2. Attack Surface",
  "3. Logging and Monitoring",
  "4. Encryption",
] as const;

export interface OrderedPillar {
  name: string;
  score: number;
  hasData: boolean;
}

const compareNatural = (a: string, b: string) =>
  a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });

// API contract is `Record<string, number>`, but defensively coerce so a
// future null/string value cannot blow up `score.toFixed(...)` callers.
// `treatMissingAsFull` makes a missing canonical pillar mean "no findings →
// 100%" rather than "no data". Only safe when `sectionScores` is provided
// (i.e. the scan ran); when undefined we still surface "no data".
const readScore = (
  scores: SectionScores,
  name: string,
  treatMissingAsFull: boolean,
): { score: number; hasData: boolean } => {
  const raw = scores[name];
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return { score: raw, hasData: true };
  }
  if (treatMissingAsFull && raw === undefined) {
    return { score: 100, hasData: true };
  }
  return { score: 0, hasData: false };
};

export function getOrderedPillars(
  sectionScores?: SectionScores,
): OrderedPillar[] {
  const scores = sectionScores ?? {};
  const treatMissingAsFull = sectionScores !== undefined;
  const remaining = new Set(Object.keys(scores));

  const canonical: OrderedPillar[] = THREATSCORE_PILLARS.map((name) => {
    remaining.delete(name);
    const { score, hasData } = readScore(scores, name, treatMissingAsFull);
    return { name, score, hasData };
  });

  const extras: OrderedPillar[] = Array.from(remaining)
    .sort(compareNatural)
    .map((name) => {
      const { score, hasData } = readScore(scores, name, false);
      return { name, score, hasData };
    });

  return [...canonical, ...extras];
}

export const THREATSCORE_SECTION_PARAM = "section";

export const compareSectionsByCanonicalOrder = (a: string, b: string) => {
  const indexA = THREATSCORE_PILLARS.indexOf(
    a as (typeof THREATSCORE_PILLARS)[number],
  );
  const indexB = THREATSCORE_PILLARS.indexOf(
    b as (typeof THREATSCORE_PILLARS)[number],
  );
  if (indexA !== -1 && indexB !== -1) return indexA - indexB;
  if (indexA !== -1) return -1;
  if (indexB !== -1) return 1;
  return compareNatural(a, b);
};
