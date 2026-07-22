interface ComplianceSectionHeaderProps {
  title: string;
  description: string;
}

/** Shared heading for the Multiple Scans tab's framework sections
 *  ("Across provider types" / "Across providers"), so both explain their
 *  aggregation axis with one consistent look. */
export const ComplianceSectionHeader = ({
  title,
  description,
}: ComplianceSectionHeaderProps) => (
  <div className="flex flex-col gap-1">
    <h3 className="text-sm font-semibold">{title}</h3>
    <p className="text-text-neutral-secondary text-xs">{description}</p>
  </div>
);
