"use client";

import Link from "next/link";
import { useState } from "react";

import {
  formatScore,
  passScore,
  sumResults,
} from "@/app/(prowler)/ai-security/_lib/results";
import type {
  AiFramework,
  AiFrameworkSection,
} from "@/app/(prowler)/ai-security/_types";
import { Button, Card, CardContent } from "@/components/shadcn";
import { SelectableCard } from "@/components/shadcn/selectable-card/selectable-card";
import { cn } from "@/lib/utils";

import { ResultBar } from "./result-bar";
import { SectionHeader } from "./section-header";

const sectionStatus = ({ pass, fail }: AiFrameworkSection) =>
  fail > 0 ? `${fail} fail` : pass > 0 ? "Pass" : "Manual";

function FrameworkDetail({ framework }: { framework: AiFramework }) {
  const totals = sumResults(framework.sections);
  const count = totals.pass + totals.fail + totals.manual;

  return (
    <Card variant="inner" className="h-full gap-4" aria-live="polite">
      <div className="flex flex-col gap-1">
        <h3 className="text-text-neutral-primary text-sm font-semibold">
          {framework.name}
        </h3>
        <p className="text-text-neutral-tertiary text-xs">
          {framework.version}, {count} {framework.unit}:{" "}
          {totals.pass + totals.fail} automated, {totals.manual} manual
        </p>
      </div>
      <p className="flex flex-wrap items-baseline gap-x-2.5">
        <span className="text-text-neutral-primary text-3xl font-semibold tabular-nums">
          {formatScore(passScore(totals))}
        </span>
        <span className="text-text-neutral-tertiary text-xs">
          of automated {framework.unit} pass: {totals.pass} pass, {totals.fail}{" "}
          fail, {totals.manual} manual
        </span>
      </p>
      {framework.note && (
        <p className="border-border-neutral-secondary bg-bg-neutral-secondary text-text-neutral-secondary rounded-lg border px-3 py-2 text-xs">
          {framework.note}
        </p>
      )}
      <ul className="flex flex-col gap-2">
        {framework.sections.map((section) => (
          <li
            key={`${section.code}${section.name}`}
            className="flex items-center gap-2.5 text-sm"
          >
            {section.code && (
              <span className="text-text-neutral-secondary w-12 shrink-0 font-mono text-xs">
                {section.code}
              </span>
            )}
            <span className="text-text-neutral-primary min-w-0 flex-1 truncate">
              {section.name}
            </span>
            <ResultBar
              label={section.name}
              {...section}
              className="w-24 shrink-0"
            />
            <span
              className={cn(
                "w-14 shrink-0 text-right text-xs font-medium",
                section.fail > 0
                  ? "text-text-error-primary"
                  : section.pass > 0
                    ? "text-text-success-primary"
                    : "text-text-neutral-tertiary",
              )}
            >
              {sectionStatus(section)}
            </span>
          </li>
        ))}
      </ul>
      <p className="border-border-neutral-secondary text-text-neutral-tertiary mt-auto border-t pt-3 text-xs">
        Manual {framework.unit} depend on code or process that configuration
        can&apos;t show.
      </p>
    </Card>
  );
}

/** The AI frameworks on the left; the picked one's sections on the right. */
export function AiCompliance({ frameworks }: { frameworks: AiFramework[] }) {
  const [selectedId, setSelectedId] = useState(frameworks[0]?.id);
  const selected =
    frameworks.find((framework) => framework.id === selectedId) ??
    frameworks[0];

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
      <CardContent className="grid grid-cols-1 gap-4 lg:grid-cols-[2fr_3fr]">
        <ul aria-label="Frameworks" className="flex min-w-0 flex-col gap-2">
          {frameworks.map((framework) => {
            const totals = sumResults(framework.sections);
            const active = framework.id === selected?.id;
            return (
              <li key={framework.id}>
                <SelectableCard
                  selected={active}
                  onClick={() => setSelectedId(framework.id)}
                  className="flex w-full flex-col gap-2"
                >
                  <span className="text-text-neutral-primary flex items-baseline justify-between gap-3 text-sm font-semibold">
                    <span className="truncate">{framework.shortName}</span>
                    <span className="tabular-nums">
                      {formatScore(passScore(totals))}
                    </span>
                  </span>
                  <span className="text-text-neutral-tertiary text-xs">
                    {framework.version},{" "}
                    {totals.pass + totals.fail + totals.manual} {framework.unit}
                  </span>
                  <ResultBar label={framework.shortName} {...totals} />
                </SelectableCard>
              </li>
            );
          })}
        </ul>
        {selected && <FrameworkDetail framework={selected} />}
      </CardContent>
    </Card>
  );
}
