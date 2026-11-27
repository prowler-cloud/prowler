"use client";

import Link from "next/link";

import { aiFindingsHref } from "@/app/(prowler)/ai-security/_lib/findings";
import { isModelVendor } from "@/app/(prowler)/ai-security/_lib/overview";
import type {
  AiStackLayer,
  AiStackProvider,
} from "@/app/(prowler)/ai-security/_types";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { useRegistryProviderDiscovery } from "@/components/providers/workflow/forms/use-registry-provider-discovery";
import { Badge, Button, Card, CardContent } from "@/components/shadcn";
import { REGISTRY_PROVIDER_DISCOVERY } from "@/lib/registry/provider-options";
import { cn } from "@/lib/utils";
import {
  SEVERITY_COLORS,
  SEVERITY_DISPLAY_NAMES,
  SEVERITY_LEVELS,
} from "@/types/severities";

import { ConnectProviderButton } from "./connect-provider-button";
import { SectionHeader } from "./section-header";

interface StackProviderProps {
  provider: AiStackProvider;
  filters: Record<string, string>;
  /** A model vendor the tenant has not installed from the Registry yet. */
  notInstalled: boolean;
}

function StackProvider({
  provider,
  filters,
  notInstalled,
}: StackProviderProps) {
  const {
    type,
    name,
    scope,
    connected,
    scanned,
    pass,
    fail,
    manual,
    severity,
    services,
  } = provider;
  const hasResults = pass + fail + manual > 0;
  const present = SEVERITY_LEVELS.filter((level) => severity[level] > 0);
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
    <Link
      href={aiFindingsHref(filters, { "filter[provider_type__in]": type })}
      aria-label={`${name}: ${fail.toLocaleString()} failed findings`}
      className="border-border-neutral-secondary bg-bg-neutral-secondary hover:bg-bg-neutral-tertiary focus-visible:ring-ring/50 flex items-center gap-3 rounded-[12px] border p-3 transition-colors focus-visible:ring-2 focus-visible:outline-none"
    >
      {identity}
      <span className="flex min-w-0 flex-1 flex-col gap-1.5">
        {/* Failed findings by severity, most severe first, sized by share. */}
        <span className="bg-bg-neutral-tertiary flex h-2 overflow-hidden rounded-full">
          {present.map((level) => (
            <span
              key={level}
              title={`${severity[level].toLocaleString()} ${SEVERITY_DISPLAY_NAMES[level].toLowerCase()}`}
              style={{
                width: `${(severity[level] / fail) * 100}%`,
                background: SEVERITY_COLORS[level],
              }}
            />
          ))}
        </span>
        {services.length > 0 && (
          <span className="flex flex-wrap gap-1">
            {services.map((service) => (
              <Badge key={service} variant="tag">
                {service}
              </Badge>
            ))}
          </span>
        )}
      </span>
      <span className="text-text-neutral-secondary shrink-0 text-xs font-medium tabular-nums">
        {fail.toLocaleString()} failed
      </span>
    </Link>
  );
}

/**
 * Where AI runs, layer by layer: the model vendors' accounts and the clouds'
 * AI services. A layer with a provider missing says what to add.
 * A provider with results opens its failed AI findings.
 */
export function AiStack({
  layers,
  filters,
}: {
  layers: AiStackLayer[];
  /** The page's scope, carried into the findings links. */
  filters: Record<string, string>;
}) {
  const { result: discovery } = useRegistryProviderDiscovery();
  // Unknown until discovery answers: keep Add Provider rather than guess.
  const installedTypes =
    discovery?.status === REGISTRY_PROVIDER_DISCOVERY.READY
      ? discovery.options.map((option) => option.type)
      : null;
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
