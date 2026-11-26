"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { aiFindingsHref } from "@/app/(prowler)/ai-security/_lib/findings";
import { isModelVendor } from "@/app/(prowler)/ai-security/_lib/overview";
import type {
  AiStackLayer,
  AiStackProvider,
} from "@/app/(prowler)/ai-security/_types";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { useRegistryProviderDiscovery } from "@/components/providers/workflow/forms/use-registry-provider-discovery";
import { Badge, Button, Card, CardContent } from "@/components/shadcn";
import { Progress } from "@/components/shadcn/progress";
import { SelectableCard } from "@/components/shadcn/selectable-card/selectable-card";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { getScoreColor } from "@/lib/compliance/score-utils";
import { splitCsvFilterValues } from "@/lib/findings-filters";
import { REGISTRY_PROVIDER_DISCOVERY } from "@/lib/registry/provider-options";
import { calculatePercentage, cn } from "@/lib/utils";

import { ConnectProviderButton } from "./connect-provider-button";
import { SectionHeader } from "./section-header";

const PROVIDER_TYPE_FILTER = "filter[provider_type__in]";

interface StackProviderProps {
  provider: AiStackProvider;
  filters: Record<string, string>;
  selected: boolean;
  onSelect: () => void;
  /** A model vendor the tenant has not installed from the Registry yet. */
  notInstalled: boolean;
}

function StackProvider({
  provider,
  filters,
  selected,
  onSelect,
  notInstalled,
}: StackProviderProps) {
  const { type, name, scope, connected, scanned, pass, fail, manual } =
    provider;
  const hasResults = pass + fail + manual > 0;
  // Pass share of pass and fail findings, as the Compliance provider coverage rows.
  const score = calculatePercentage(pass, pass + fail);
  const identity = (
    <>
      {/* Greyed out like the framework cards' providers without a completed scan. */}
      <span
        className={cn(
          "inline-flex",
          connected && !scanned && "opacity-35 grayscale",
        )}
      >
        <ProviderTypeIcon type={type} size={28} />
      </span>
      <span className="flex w-32 min-w-0 shrink-0 flex-col">
        <span className="text-text-neutral-primary truncate text-sm font-medium">
          {name}
        </span>
        <span className="text-text-neutral-tertiary truncate text-xs">
          {connected ? scope : "Not connected"}
        </span>
      </span>
    </>
  );

  if (!connected || !hasResults) {
    return (
      <div className="flex items-center gap-3">
        <div className="flex min-w-0 flex-1 items-center gap-3 p-3">
          {identity}
          {connected && (
            <Badge variant="tag">
              {scanned ? "No AI services found" : "No completed scan yet"}
            </Badge>
          )}
        </div>
        {!connected &&
          (notInstalled ? (
            // The wizard lists only installed Registry providers, so install it first.
            <Button asChild>
              <Link
                href={`/registry?${new URLSearchParams({ "filter[search]": name })}`}
              >
                Install from Registry
              </Link>
            </Button>
          ) : (
            <ConnectProviderButton />
          ))}
        {connected && !scanned && (
          <Button asChild variant="link" size="link-sm">
            <Link href="/scans">Launch scan</Link>
          </Button>
        )}
      </div>
    );
  }

  return (
    <div className="flex items-center gap-3">
      <SelectableCard
        selected={selected}
        onClick={onSelect}
        title={
          selected ? "Show every AI provider" : `Show only ${name} results`
        }
        className="flex min-w-0 flex-1 items-center gap-3"
      >
        {identity}
        <span className="flex min-w-0 flex-1 flex-col gap-1.5">
          <Progress
            aria-label={`${name} pass findings`}
            value={score}
            variant={getScoreColor(score)}
          />
          <span className="text-text-neutral-tertiary text-xs whitespace-nowrap">
            {pass}/{pass + fail} · {manual} manual
          </span>
        </span>
      </SelectableCard>
      <Button asChild variant="link" size="link-sm">
        <Link
          href={aiFindingsHref(filters, { "filter[provider_type__in]": type })}
          aria-label={`${name}: ${score}%, ${fail} failed findings`}
        >
          {score}%
        </Link>
      </Button>
    </div>
  );
}

/**
 * Where AI runs, layer by layer: the model vendors' accounts and the clouds'
 * AI services. A layer with a provider missing says what to add.
 * A connected provider filters the page to its type; picking it again clears it.
 */
export function AiStack({
  layers,
  filters,
}: {
  layers: AiStackLayer[];
  /** The page's scope, carried into the findings links. */
  filters: Record<string, string>;
}) {
  const searchParams = useSearchParams();
  const { navigateWithParams } = useUrlFilters();
  const { result: discovery } = useRegistryProviderDiscovery();
  // Unknown until discovery answers: keep Add Provider rather than guess.
  const installedTypes =
    discovery?.status === REGISTRY_PROVIDER_DISCOVERY.READY
      ? discovery.options.map((option) => option.type)
      : null;
  const selected = splitCsvFilterValues(
    searchParams.get(PROVIDER_TYPE_FILTER) ?? undefined,
  );

  const toggle = (type: string) =>
    navigateWithParams((params) => {
      if (selected.length === 1 && selected[0] === type) {
        params.delete(PROVIDER_TYPE_FILTER);
      } else {
        params.set(PROVIDER_TYPE_FILTER, type);
      }
    });

  return (
    <Card variant="base" className="w-full min-w-0">
      <SectionHeader
        title="Your AI stack"
        description="Each layer is scanned through its own provider. A gap in one layer stays open whatever the others score."
      />
      <CardContent>
        <ul
          className={cn(
            "grid grid-cols-1 gap-4",
            layers.length > 1 && "xl:grid-cols-2",
          )}
        >
          {layers.map((layer) => (
            <li key={layer.id} className="min-w-0">
              <Card variant="inner" className="h-full gap-4">
                <div className="flex flex-col gap-1">
                  <div className="flex items-baseline justify-between gap-3">
                    <h3 className="text-text-neutral-primary text-sm font-semibold">
                      {layer.name}
                    </h3>
                    <span className="text-text-error-primary shrink-0 text-xs font-medium">
                      {layer.providers
                        .reduce((sum, provider) => sum + provider.fail, 0)
                        .toLocaleString()}{" "}
                      failed
                    </span>
                  </div>
                  <p className="text-text-neutral-tertiary text-xs">
                    {layer.description}
                  </p>
                </div>
                <ul className="flex flex-col gap-3">
                  {layer.providers.map((provider) => (
                    <li key={provider.name}>
                      <StackProvider
                        provider={provider}
                        filters={filters}
                        selected={selected.includes(provider.type)}
                        onSelect={() => toggle(provider.type)}
                        notInstalled={
                          isModelVendor(provider.type) &&
                          installedTypes !== null &&
                          !installedTypes.includes(provider.type)
                        }
                      />
                    </li>
                  ))}
                </ul>
              </Card>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
