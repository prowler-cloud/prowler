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
  label,
  icon,
  score,
}: {
  id: string;
  framework: string;
  label: string;
  icon?: string | StaticImageData;
  score: number;
}): WatchlistItem => {
  return {
    key: id,
    icon: <ComplianceIcon src={icon} label={framework} />,
    label,
    value: `${score}%`,
  };
};
