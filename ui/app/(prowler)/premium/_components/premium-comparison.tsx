import { Check, Minus } from "lucide-react";
import Link from "next/link";

import { PremiumBadge } from "@/components/shared/premium-badge";
import { PREMIUM_COMPARISON_ROWS } from "@/lib/premium";
import { CLOUD_UPGRADE_SURFACE } from "@/types/cloud-upgrade";

const EDITIONS = [
  {
    key: "localServer",
    name: "Local Server",
    detail: "Open Source · you are here",
  },
  { key: "cloud", name: "Prowler Cloud", detail: "Hosted by Prowler" },
  { key: "privateCloud", name: "Private Cloud", detail: "In your environment" },
] as const;

function Availability({ value }: { value: boolean | string }) {
  if (typeof value === "string") {
    return <span className="text-text-neutral-primary text-sm">{value}</span>;
  }

  return value ? (
    <Check aria-label="Included" className="text-text-success-primary size-4" />
  ) : (
    <Minus
      aria-label="Not included"
      className="text-text-neutral-tertiary size-4"
    />
  );
}

export function PremiumComparison() {
  return (
    <div className="border-border-neutral-secondary overflow-x-auto rounded-xl border">
      <table className="w-full min-w-[640px] text-left text-sm">
        <thead className="bg-bg-neutral-secondary">
          <tr>
            <th scope="col" className="px-4 py-3 font-medium">
              Capability
            </th>
            {EDITIONS.map((edition) => (
              <th key={edition.key} scope="col" className="px-4 py-3">
                <div className="font-medium">{edition.name}</div>
                <div className="text-text-neutral-tertiary text-xs font-normal">
                  {edition.detail}
                </div>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {PREMIUM_COMPARISON_ROWS.map((row) => (
            <tr
              key={row.capability}
              className="border-border-neutral-secondary border-t"
            >
              <th scope="row" className="px-4 py-3 font-normal">
                <div className="flex flex-wrap items-center gap-2">
                  {row.href ? (
                    <Link
                      href={row.href}
                      className="underline-offset-2 hover:underline"
                    >
                      {row.capability}
                    </Link>
                  ) : (
                    <span>{row.capability}</span>
                  )}
                  {row.feature && (
                    <PremiumBadge
                      feature={row.feature}
                      surface={CLOUD_UPGRADE_SURFACE.PREMIUM_PAGE}
                      compact
                    />
                  )}
                </div>
              </th>
              {EDITIONS.map((edition) => (
                <td key={edition.key} className="px-4 py-3">
                  <Availability value={row[edition.key]} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
