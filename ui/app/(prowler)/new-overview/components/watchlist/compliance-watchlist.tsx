import Image, { type StaticImageData } from "next/image";

import { WatchlistCard, type WatchlistItem } from "./watchlist-card";

const ComplianceIcon = ({
  src,
  label,
}: {
  src?: string | StaticImageData;
  label: string;
}) => (
  <div className="relative size-3">
    {src ? (
      <Image
        src={src}
        alt={`${label} framework`}
        fill
        className="object-contain"
      />
    ) : (
      <div className="bg-bg-data-muted size-full rounded-sm" aria-hidden />
    )}
  </div>
);

export const ComplianceWatchlist = ({ items }: { items: WatchlistItem[] }) => {
  return (
    <WatchlistCard
      title="Compliance Watchlist"
      items={items}
      ctaLabel="Compliance Dashboard"
      ctaHref="/compliance"
      emptyState={{
        message: "This space is looking empty.",
        description: "to add compliance frameworks to your watchlist.",
        linkText: "Compliance Dashboard",
      }}
    />
  );
};

export const buildComplianceWatchlistItem = ({
  id,
  framework,
  version,
  requirements_passed,
  total_requirements,
  icon,
}: {
  id: string;
  framework: string;
  version: string;
  requirements_passed: number;
  total_requirements: number;
  icon?: string | StaticImageData;
}): WatchlistItem => {
  const totalRequirements = Number(total_requirements) || 0;
  const passedRequirements = Number(requirements_passed) || 0;

  const score =
    totalRequirements > 0
      ? Math.round((passedRequirements / totalRequirements) * 100)
      : 0;

  return {
    key: id,
    icon: <ComplianceIcon src={icon} label={framework} />,
    label: version ? `${framework} - ${version}` : framework,
    value: `${score}%`,
  };
};
