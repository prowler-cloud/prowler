import Link from "next/link";

export const LinkToFindings = () => {
  return (
    <Link
      href="/findings?sort=-severity,-last_seen_at&filter[status__in]=FAIL&filter[delta]=new"
      aria-label="Go to Findings page"
      className="text-button-tertiary hover:text-button-tertiary-hover text-sm font-medium transition-colors"
    >
      Check out on Findings
    </Link>
  );
};
