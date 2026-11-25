"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { aiFindingsHref } from "@/app/(prowler)/ai-security/_lib/findings";
import {
  formatScore,
  passScore,
  sumResults,
} from "@/app/(prowler)/ai-security/_lib/results";
import type {
  AiStackLayer,
  AiStackProvider,
} from "@/app/(prowler)/ai-security/_types";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Button, Card, CardContent } from "@/components/shadcn";
import { SelectableCard } from "@/components/shadcn/selectable-card/selectable-card";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { splitCsvFilterValues } from "@/lib/findings-filters";
import { cn } from "@/lib/utils";

import { ConnectProviderButton } from "./connect-provider-button";
import { ResultBar, ResultLegend } from "./result-bar";
import { SectionHeader } from "./section-header";

const PROVIDER_TYPE_FILTER = "filter[provider_type__in]";

interface StackProviderProps {
  provider: AiStackProvider;
  selected: boolean;
  onSelect: () => void;
}

function StackProvider({ provider, selected, onSelect }: StackProviderProps) {
  const { type, name, scope, connected } = provider;
  const identity = (
    <>
      <ProviderTypeIcon type={type} size={28} />
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

  return (
    <div className="flex items-center gap-3">
      {connected ? (
        <>
          <SelectableCard
            selected={selected}
            onClick={onSelect}
            title={
              selected ? "Show every AI provider" : `Show only ${name} results`
            }
            className="flex min-w-0 flex-1 items-center gap-3 px-3 py-2"
          >
            {identity}
            <ResultBar label={name} {...provider} className="min-w-0 flex-1" />
          </SelectableCard>
          <Button asChild variant="link" size="link-sm">
            <Link
              href={aiFindingsHref({ "filter[provider_type__in]": type })}
              aria-label={`${name}: ${formatScore(passScore(provider))}, ${provider.fail} failed findings`}
            >
              {formatScore(passScore(provider))}
            </Link>
          </Button>
        </>
      ) : (
        <>
          <div className="flex flex-1 items-center gap-3 px-3 py-2">
            {identity}
          </div>
          <ConnectProviderButton />
        </>
      )}
    </div>
  );
}

/**
 * Where AI runs, layer by layer: the vendor accounts, the cloud services and
 * the developer platforms. A layer with a provider missing says what to add.
 * A connected provider filters the page to its type; picking it again clears it.
 */
export function AiStack({ layers }: { layers: AiStackLayer[] }) {
  const searchParams = useSearchParams();
  const { navigateWithParams } = useUrlFilters();
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
        aside={<ResultLegend />}
      />
      <CardContent>
        <ul
          className={cn(
            "grid grid-cols-1 gap-4",
            layers.length > 1 && "xl:grid-cols-3",
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
                      {sumResults(layer.providers).fail.toLocaleString()} failed
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
                        selected={selected.includes(provider.type)}
                        onSelect={() => toggle(provider.type)}
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
