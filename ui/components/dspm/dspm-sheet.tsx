"use client";

import { Sparkles } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import { LoadingState } from "@/components/shadcn/spinner/loading-state";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet/sheet";

import { DspmScanProgress, type ScanStatus } from "./dspm-scan-progress";
import { DspmTable, type DspmEntry } from "./dspm-table";

export type { DspmEntry };

const CATALOG: DspmEntry[] = [
  {
    datastore_id: "s3://acme-customers-prod",
    service: "s3",
    classification: "PII",
    confidence: 0.96,
    risk_score: 10,
    evidence:
      "Found SSN-format strings in 7/10 sampled objects; email + full name combinations in 9/10",
    recommendation:
      "Enable SSE-KMS encryption, attach restrictive bucket policy, enable Block Public Access",
  },
  {
    datastore_id: "s3://acme-payments-archive",
    service: "s3",
    classification: "Financial",
    confidence: 0.91,
    risk_score: 9,
    evidence:
      "Detected credit card PANs (Luhn-valid) and IBAN strings in 8/10 sampled archives",
    recommendation:
      "Enable SSE-KMS, turn on versioning + Object Lock, restrict to PCI-scoped IAM roles",
  },
  {
    datastore_id: "rds://patients-db-primary",
    service: "rds",
    classification: "Health",
    confidence: 0.89,
    risk_score: 8,
    evidence:
      "Rows contain ICD-10 codes, patient identifiers, and diagnosis free-text in 10/10 sampled rows",
    recommendation:
      "Disable public accessibility, place behind a private subnet, restrict to HIPAA-scoped roles",
  },
  {
    datastore_id: "dynamodb://billing-events",
    service: "dynamodb",
    classification: "Financial",
    confidence: 0.88,
    risk_score: 8,
    evidence:
      "Items contain charge_amount, last4_cc, and merchant_id in 9/10 sampled items",
    recommendation:
      "Enable encryption at rest with customer-managed KMS, restrict global table replicas to PCI regions",
  },
  {
    datastore_id: "rds://payroll-prod",
    service: "rds",
    classification: "Financial",
    confidence: 0.93,
    risk_score: 7,
    evidence:
      "Columns include salary, tax_id, and bank_account in 10/10 sampled rows",
    recommendation:
      "Enable automated backups with 30-day retention, rotate KMS key, enforce least-privilege role",
  },
  {
    datastore_id: "dynamodb://user-sessions",
    service: "dynamodb",
    classification: "PII",
    confidence: 0.84,
    risk_score: 7,
    evidence:
      "Items contain user_email and session_token fields in 10/10 sampled items",
    recommendation:
      "Set TTL to 24h, enable PITR, rotate session signing key quarterly",
  },
  {
    datastore_id: "rds://analytics-warehouse",
    service: "rds",
    classification: "Unknown",
    confidence: 0.42,
    risk_score: 3,
    evidence:
      "Sampled rows contain aggregate counts and anonymized identifiers; insufficient signal for confident classification",
    recommendation:
      "Re-run with expanded sample size; verify anonymization invariants documented",
  },
  {
    datastore_id: "s3://acme-marketing-assets",
    service: "s3",
    classification: "Public",
    confidence: 0.99,
    risk_score: 1,
    evidence:
      "All 10 samples are PNG/JPG marketing collateral with no detected sensitive content",
    recommendation:
      "No action required; current public-read ACL is intentional",
  },
  {
    datastore_id: "dynamodb://feature-flags",
    service: "dynamodb",
    classification: "Public",
    confidence: 0.97,
    risk_score: 1,
    evidence:
      "Items contain feature names and boolean flags only; no sensitive content detected",
    recommendation: "No action required",
  },
];

const SCAN_LABELS: Record<Exclude<ScanStatus, "done">, string> = {
  discovering: "Discovering datastores in your AWS environment...",
  sampling: "Sampling 10 objects from each datastore...",
  classifying: "Classifying samples with Lighthouse AI...",
};

interface DspmSheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export const DspmSheet = ({ open, onOpenChange }: DspmSheetProps) => {
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const highRisk = CATALOG.filter((e) => e.risk_score >= 8).length;
  const isScanning = status !== null && status !== "done";

  useEffect(() => {
    if (!open) {
      timersRef.current.forEach(clearTimeout);
      timersRef.current = [];
      setStatus(null);
      return;
    }

    setStatus("discovering");
    timersRef.current = [
      setTimeout(() => setStatus("sampling"), 1000),
      setTimeout(() => setStatus("classifying"), 2000),
      setTimeout(() => setStatus("done"), 3200),
    ];

    return () => {
      timersRef.current.forEach(clearTimeout);
      timersRef.current = [];
    };
  }, [open]);

  const handleRescan = () => {
    timersRef.current.forEach(clearTimeout);
    setStatus("discovering");
    timersRef.current = [
      setTimeout(() => setStatus("sampling"), 1000),
      setTimeout(() => setStatus("classifying"), 2000),
      setTimeout(() => setStatus("done"), 3200),
    ];
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="flex w-full flex-col gap-4 overflow-y-auto sm:max-w-3xl"
      >
        <SheetHeader>
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1">
              <SheetTitle className="flex items-center gap-2">
                <Sparkles className="size-5 text-amber-500" />
                DSPM Analysis
                <span className="text-text-neutral-secondary text-sm font-normal">
                  · powered by Lighthouse AI
                </span>
              </SheetTitle>
              <SheetDescription>
                Classified datastores discovered during your last scan
              </SheetDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={handleRescan}
              disabled={isScanning}
            >
              Re-scan
            </Button>
          </div>
        </SheetHeader>

        <div className="flex-1">
          {status === "done" ? (
            <DspmTable data={CATALOG} />
          ) : (
            <div className="flex flex-col gap-6 py-4">
              <DspmScanProgress status={status ?? "discovering"} />
              <LoadingState
                label={
                  SCAN_LABELS[
                    (status ?? "discovering") as Exclude<ScanStatus, "done">
                  ]
                }
              />
            </div>
          )}
        </div>

        {status === "done" && (
          <div className="text-text-neutral-secondary border-border-neutral-secondary border-t pt-3 text-xs">
            Last scan: just now · {CATALOG.length} datastores classified ·{" "}
            {highRisk} high-risk
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
};
