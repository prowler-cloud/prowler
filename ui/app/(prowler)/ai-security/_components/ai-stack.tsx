import Link from "next/link";

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

import { ConnectProviderButton } from "./connect-provider-button";
import { ResultBar, ResultLegend } from "./result-bar";
import { SectionHeader } from "./section-header";

function StackProvider({ provider }: { provider: AiStackProvider }) {
  const { type, name, scope, connected } = provider;

  return (
    <div className="flex items-center gap-3">
      <ProviderTypeIcon type={type} size={28} />
      <div className="flex w-32 min-w-0 shrink-0 flex-col">
        <span className="text-text-neutral-primary truncate text-sm font-medium">
          {name}
        </span>
        <span className="text-text-neutral-tertiary truncate text-xs">
          {connected ? scope : "Not connected"}
        </span>
      </div>
      {connected ? (
        <>
          <ResultBar label={name} {...provider} className="min-w-0 flex-1" />
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
        <div className="flex flex-1 justify-end">
          <ConnectProviderButton />
        </div>
      )}
    </div>
  );
}

/**
 * Where AI runs, layer by layer: the vendor accounts, the cloud services and
 * the developer platforms. A layer with a provider missing says what to add.
 */
export const AiStack = ({ layers }: { layers: AiStackLayer[] }) => (
  <Card variant="base" className="w-full min-w-0">
    <SectionHeader
      title="Your AI stack"
      description="Each layer is scanned through its own provider. A gap in one layer stays open whatever the others score."
      aside={<ResultLegend />}
    />
    <CardContent>
      <ul className="grid grid-cols-1 gap-4 xl:grid-cols-3">
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
                    <StackProvider provider={provider} />
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
