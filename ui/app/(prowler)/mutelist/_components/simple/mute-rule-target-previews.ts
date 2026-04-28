import {
  adaptFindingsByResourceResponse,
  getLatestFindings,
  type ResourceDrawerFinding,
} from "@/actions/findings";
import { MuteRuleData } from "@/actions/mute-rules/types";

export interface MuteRuleTableData extends MuteRuleData {
  targetLabels: string[];
  targetSummaryLabel: string;
  hiddenTargetCount: number;
}

export function formatMuteRuleTargetPreview(
  finding: Pick<
    ResourceDrawerFinding,
    "checkTitle" | "checkId" | "resourceName" | "resourceUid"
  >,
): string {
  const checkTitle = finding.checkTitle?.trim();
  const checkId = finding.checkId?.trim();
  const resourceName = finding.resourceName?.trim();
  const resourceUid = finding.resourceUid?.trim();

  const left = checkTitle || checkId || "Unknown finding";
  const right = resourceName || resourceUid;

  return right ? `${left} • ${right}` : left;
}

export async function hydrateMuteRuleTargetPreviews(
  muteRules: MuteRuleData[],
): Promise<MuteRuleTableData[]> {
  const targetUids = Array.from(
    new Set(muteRules.flatMap((muteRule) => muteRule.attributes.finding_uids)),
  );

  const previewByUid = new Map<string, string>();

  if (targetUids.length > 0) {
    const findings = await getLatestFindings({
      pageSize: targetUids.length,
      filters: {
        "filter[uid__in]": targetUids.join(","),
      },
    });

    const adaptedFindings = adaptFindingsByResourceResponse(findings);

    adaptedFindings.forEach((finding) => {
      previewByUid.set(finding.uid, formatMuteRuleTargetPreview(finding));
    });
  }

  return muteRules.map((muteRule) => {
    const targetLabels = muteRule.attributes.finding_uids.map(
      (uid) => previewByUid.get(uid) ?? uid,
    );
    const targetSummaryLabel =
      targetLabels[0] ||
      `${muteRule.attributes.finding_uids.length} ${
        muteRule.attributes.finding_uids.length === 1 ? "finding" : "findings"
      }`;

    return {
      ...muteRule,
      targetLabels,
      targetSummaryLabel,
      hiddenTargetCount: Math.max(targetLabels.length - 1, 0),
    };
  });
}
