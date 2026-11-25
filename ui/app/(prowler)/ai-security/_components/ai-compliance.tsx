import Link from "next/link";

import {
  isModelVendor,
  narrowScope,
} from "@/app/(prowler)/ai-security/_lib/overview";
import {
  formatScore,
  passScore,
} from "@/app/(prowler)/ai-security/_lib/results";
import type { AiFramework } from "@/app/(prowler)/ai-security/_types";
import { buildCrossProviderDetailHref } from "@/app/(prowler)/compliance/_lib/cross-provider-frameworks";
import { Button, Card, CardContent } from "@/components/shadcn";

import { ResultBar } from "./result-bar";
import { SectionHeader } from "./section-header";

interface AiComplianceProps {
  frameworks: AiFramework[];
  /** The page's provider filters narrowed to the AI-SPM providers. */
  filters: Record<string, string>;
}

/**
 * The AI frameworks with their scores. Each opens its Compliance detail across
 * the model vendors in scope, as the Compliance page's framework cards do.
 */
export function AiCompliance({ frameworks, filters }: AiComplianceProps) {
  const scope = narrowScope(filters, isModelVendor) ?? {};

  return (
    <Card variant="base" className="w-full min-w-0">
      <SectionHeader
        title="Compliance frameworks"
        description="Every framework is scored from the same scan. Manual requirements count as neither pass nor fail."
        aside={
          <Button asChild variant="link" size="link-sm">
            <Link href="/compliance">Open in Compliance</Link>
          </Button>
        }
      />
      <CardContent>
        <ul
          aria-label="Frameworks"
          className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3"
        >
          {frameworks.map((framework) => (
            <li key={framework.id} className="min-w-0">
              <Link
                href={buildCrossProviderDetailHref(
                  {
                    complianceId: framework.id,
                    title: framework.title,
                    version: framework.version,
                  },
                  scope,
                )}
                className="focus-visible:ring-button-primary/50 block h-full rounded-[12px] outline-none focus-visible:ring-2"
              >
                <Card variant="inner" interactive className="h-full gap-2">
                  <span className="text-text-neutral-primary flex items-baseline justify-between gap-3 text-sm font-semibold">
                    <span className="truncate">{framework.shortName}</span>
                    <span className="tabular-nums">
                      {formatScore(passScore(framework))}
                    </span>
                  </span>
                  <span className="text-text-neutral-tertiary truncate text-xs">
                    {framework.name}, {framework.version}:{" "}
                    {framework.pass + framework.fail + framework.manual}{" "}
                    {framework.unit}, {framework.manual} manual
                  </span>
                  <ResultBar label={framework.shortName} {...framework} />
                </Card>
              </Link>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
