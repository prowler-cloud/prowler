import {
  type Severity,
  SeverityBadge,
  SeverityValues,
} from "@/components/shadcn/table/severity-badge";

const KNOWN = Object.values(SeverityValues) as string[];

/** The shared severity chip for known severities; unknown values show as text. */
export function RealtimeSeverity({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  return KNOWN.includes(normalized) ? (
    <SeverityBadge severity={normalized as Severity} />
  ) : (
    <span className="text-text-neutral-primary text-sm capitalize">
      {severity || "Unknown"}
    </span>
  );
}
