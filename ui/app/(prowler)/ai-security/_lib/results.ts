import type { AiResultCounts } from "@/app/(prowler)/ai-security/_types";

/** Share of automated checks that pass. Manual checks have no verdict, so they stay out. */
export const passScore = ({
  pass,
  fail,
}: Pick<AiResultCounts, "pass" | "fail">) =>
  pass + fail === 0 ? null : Math.round((pass / (pass + fail)) * 100);

export const formatScore = (score: number | null) =>
  score === null ? "—" : `${score}%`;

export const sumResults = (items: AiResultCounts[]): AiResultCounts =>
  items.reduce<AiResultCounts>(
    (sum, item) => ({
      pass: sum.pass + item.pass,
      fail: sum.fail + item.fail,
      manual: sum.manual + item.manual,
    }),
    { pass: 0, fail: 0, manual: 0 },
  );
