import Link from "next/link";

import { RealtimePanelError } from "@/app/(prowler)/realtime/_components/shared/realtime-panel-error";
import { modeLabel } from "@/app/(prowler)/realtime/_lib/display";
import { configurationHref } from "@/app/(prowler)/realtime/_lib/routes";
import {
  REALTIME_MODE,
  type RealtimeResult,
  type RealtimeSimulationPayload,
} from "@/app/(prowler)/realtime/_types";
import {
  Alert,
  AlertDescription,
  Button,
  Card,
  CardContent,
  Progress,
} from "@/components/shadcn";

interface SimulationCardProps {
  providerId: string;
  demo: boolean;
  result: RealtimeResult<RealtimeSimulationPayload>;
}

interface FigureProps {
  value: number;
  label: string;
}

function Figure({ value, label }: FigureProps) {
  return (
    <Card variant="inner" padding="md">
      <CardContent className="flex flex-col">
        <span className="text-text-neutral-primary text-2xl font-bold">
          {value.toLocaleString()}
        </span>
        <span className="text-text-neutral-tertiary text-xs">{label}</span>
      </CardContent>
    </Card>
  );
}

/** What the current policy would do with today's open failures. Changes nothing. */
export function SimulationCard({
  providerId,
  demo,
  result,
}: SimulationCardProps) {
  return (
    <Card variant="base" padding="lg" className="h-full">
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <h3 className="text-text-neutral-primary text-base font-semibold">
            If the policy ran today
          </h3>
          <p className="text-text-neutral-tertiary text-sm">
            {result.ok
              ? `${modeLabel(result.data.mode)}, applied to the ${result.data.open.toLocaleString()} open ${result.data.open === 1 ? "failure" : "failures"}. Nothing changes.`
              : "What the policy would do with the open failures."}
          </p>
        </div>
        {!result.ok ? (
          <RealtimePanelError failure={result} />
        ) : (
          <>
            <div className="grid grid-cols-3 gap-2">
              <Figure
                value={result.data.would_fix_in_account}
                label="Fixed in the account"
              />
              <Figure
                value={result.data.would_propose_in_code}
                label="Pull requests"
              />
              <Figure
                value={result.data.needs_a_person}
                label="Need a person"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-text-neutral-tertiary">Automated</span>
                <span className="text-text-neutral-primary font-semibold">
                  {Math.round(result.data.automation_share)}%
                </span>
              </div>
              <Progress
                value={result.data.automation_share}
                aria-label="Share of findings handled automatically"
              />
              {result.data.outside_frameworks > 0 && (
                <span className="text-text-neutral-tertiary text-xs">
                  {result.data.outside_frameworks.toLocaleString()} of them sit
                  outside the enforced frameworks and stay untouched.
                </span>
              )}
            </div>
            {result.data.mode === REALTIME_MODE.AUTO && result.data.dry_run && (
              <Alert variant="warning">
                <AlertDescription className="flex flex-wrap items-center gap-1">
                  Dry run is on: fixes are recorded, not applied.
                  {!demo && (
                    <Button variant="link" size="link-sm" asChild>
                      <Link href={configurationHref(providerId, "enforcement")}>
                        Review in Configuration
                      </Link>
                    </Button>
                  )}
                </AlertDescription>
              </Alert>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
