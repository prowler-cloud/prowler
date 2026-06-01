"use client";

import {
  CircleArrowRight,
  Database,
  HardDrive,
  Layers,
} from "lucide-react";
import { Fragment, useState } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import {
  Section,
  SectionContent,
  SectionHeader,
  SectionTitle,
} from "@/components/shadcn/section/section";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table/table";
import { cn } from "@/lib/utils";

import { RiskBadge } from "./risk-badge";

export type DspmService = "s3" | "rds" | "dynamodb";
export type DspmClassification =
  | "PII"
  | "Financial"
  | "Health"
  | "Public"
  | "Unknown";

export interface DspmEntry {
  datastore_id: string;
  service: DspmService;
  classification: DspmClassification;
  confidence: number;
  risk_score: number;
  evidence: string;
  recommendation: string;
}

const SERVICE_ICONS = {
  s3: HardDrive,
  rds: Database,
  dynamodb: Layers,
} as const;

const CLASSIFICATION_STYLES: Record<DspmClassification, string> = {
  PII: "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300",
  Financial:
    "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900 dark:bg-orange-950 dark:text-orange-300",
  Health:
    "border-purple-200 bg-purple-50 text-purple-700 dark:border-purple-900 dark:bg-purple-950 dark:text-purple-300",
  Public:
    "border-green-200 bg-green-50 text-green-700 dark:border-green-900 dark:bg-green-950 dark:text-green-300",
  Unknown:
    "border-neutral-200 bg-neutral-50 text-neutral-700 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-300",
};

const seedPrompt = (row: DspmEntry): string =>
  `Analyze this DSPM finding from our latest scan:\n\n- Datastore: ${row.datastore_id}\n- Service: ${row.service}\n- Classification: ${row.classification} (confidence ${row.confidence})\n- Risk score: ${row.risk_score}/10\n- Evidence: ${row.evidence}\n- Recommendation: ${row.recommendation}\n\nExplain the exposure and propose a Terraform fix.`;

interface ClassificationBadgeProps {
  classification: DspmClassification;
}

const ClassificationBadge = ({ classification }: ClassificationBadgeProps) => (
  <Badge
    variant="outline"
    className={cn(
      "w-20 justify-center",
      CLASSIFICATION_STYLES[classification],
    )}
  >
    {classification}
  </Badge>
);

interface DspmTableProps {
  data: DspmEntry[];
}

export const DspmTable = ({ data }: DspmTableProps) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const sorted = [...data].sort((a, b) => b.risk_score - a.risk_score);

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Datastore</TableHead>
          <TableHead>Classification</TableHead>
          <TableHead>Confidence</TableHead>
          <TableHead>Risk</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {sorted.map((row) => {
          const Icon = SERVICE_ICONS[row.service];
          const isExpanded = expandedId === row.datastore_id;
          return (
            <Fragment key={row.datastore_id}>
              <TableRow
                data-state={isExpanded ? "selected" : undefined}
                className="cursor-pointer"
                onClick={() =>
                  setExpandedId(isExpanded ? null : row.datastore_id)
                }
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Icon className="text-text-neutral-secondary size-4 shrink-0" />
                    <span className="font-mono text-xs">
                      {row.datastore_id}
                    </span>
                  </div>
                </TableCell>
                <TableCell>
                  <ClassificationBadge classification={row.classification} />
                </TableCell>
                <TableCell className="text-text-neutral-secondary tabular-nums">
                  {Math.round(row.confidence * 100)}%
                </TableCell>
                <TableCell>
                  <RiskBadge score={row.risk_score} />
                </TableCell>
              </TableRow>
              {isExpanded && (
                <TableRow
                  data-state="selected"
                  className="cursor-default"
                >
                  <TableCell colSpan={4} className="py-4">
                    <div className="flex flex-col gap-4">
                      <Section>
                        <SectionHeader>
                          <SectionTitle className="text-sm leading-tight">
                            Evidence
                          </SectionTitle>
                        </SectionHeader>
                        <SectionContent>
                          <p className="text-text-neutral-primary text-sm">
                            {row.evidence}
                          </p>
                        </SectionContent>
                      </Section>
                      <Section>
                        <SectionHeader>
                          <SectionTitle className="text-sm leading-tight">
                            Recommendation
                          </SectionTitle>
                        </SectionHeader>
                        <SectionContent>
                          <p className="text-text-neutral-primary text-sm">
                            {row.recommendation}
                          </p>
                        </SectionContent>
                      </Section>
                      <div>
                        <a
                          href={`/lighthouse?${new URLSearchParams({ prompt: seedPrompt(row) }).toString()}`}
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center gap-1.5 rounded-lg px-4 py-3 text-sm font-bold text-slate-900 transition-opacity hover:opacity-90"
                          style={{ background: "var(--gradient-lighthouse)" }}
                        >
                          <CircleArrowRight className="size-5" />
                          Analyze with Lighthouse AI
                        </a>
                      </div>
                    </div>
                  </TableCell>
                </TableRow>
              )}
            </Fragment>
          );
        })}
      </TableBody>
    </Table>
  );
};
