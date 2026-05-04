import {
  FailedSection,
  Framework,
  REQUIREMENT_STATUS,
  TOP_FAILED_DATA_TYPE,
  TopFailedResult,
} from "@/types/compliance";

import {
  compareSectionsByCanonicalOrder,
  THREATSCORE_PILLARS,
} from "./threatscore-pillars";

// Builds the Top Failed Sections data for ThreatScore: every canonical pillar
// is always present (zero-fill) so the chart remains meaningful even when
// only one or two pillars have failures. Sections returned by the data that
// are not in the canonical list are appended afterwards in canonical order.
export const getTopFailedSections = (
  mappedData: Framework[],
): TopFailedResult => {
  const totals = new Map<string, number>();
  const seen = new Set<string>();

  THREATSCORE_PILLARS.forEach((name) => {
    totals.set(name, 0);
    seen.add(name);
  });

  mappedData.forEach((framework) => {
    framework.categories.forEach((category) => {
      seen.add(category.name);
      category.controls.forEach((control) => {
        control.requirements.forEach((requirement) => {
          if (requirement.status === REQUIREMENT_STATUS.FAIL) {
            totals.set(category.name, (totals.get(category.name) ?? 0) + 1);
          }
        });
      });
    });
  });

  const items: FailedSection[] = Array.from(seen)
    .sort(compareSectionsByCanonicalOrder)
    .map((name) => ({ name, total: totals.get(name) ?? 0 }));

  return { items, type: TOP_FAILED_DATA_TYPE.SECTIONS };
};
