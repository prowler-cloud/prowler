import { ShieldCheck } from "lucide-react";
import Link from "next/link";

import { CrossProviderErrorAlert } from "@/app/(prowler)/compliance/_components/cross-provider-error-alert";
import { CrossProviderFrameworkCard } from "@/app/(prowler)/compliance/_components/cross-provider-framework-card";
import type { CrossProviderFrameworkSummary } from "@/app/(prowler)/compliance/_types";
import { ComplianceFrameworkGrid } from "@/components/compliance/compliance-framework-grid";
import {
  Button,
  Card,
  CardContent,
  StatusPanel,
  StatusPanelActions,
  StatusPanelBody,
  StatusPanelDescription,
  StatusPanelIcon,
  StatusPanelTitle,
} from "@/components/shadcn";
import { STATUS_PANEL_LAYOUT } from "@/components/shadcn/status-panel";

import { SectionHeader } from "./section-header";

/** The Registry's compliance packages, where the AI frameworks install from. */
const REGISTRY_COMPLIANCE_HREF = "/registry?filter%5Bcapability%5D=compliance";

/** The AI frameworks as the Compliance page's universal framework cards; null when they could not be loaded. */
export const AiCompliance = ({
  frameworks,
}: {
  frameworks: CrossProviderFrameworkSummary[] | null;
}) => (
  <Card variant="base" className="w-full min-w-0">
    <SectionHeader
      title="Compliance frameworks"
      description="Universal frameworks aggregated across every compatible provider type, using the latest completed scan of each provider."
      aside={
        <Button asChild variant="link" size="link-sm">
          {!frameworks || frameworks.length > 0 ? (
            <Link href="/compliance">Open in Compliance</Link>
          ) : (
            <Link href={REGISTRY_COMPLIANCE_HREF}>Browse Registry</Link>
          )}
        </Button>
      }
    />
    <CardContent>
      {!frameworks ? (
        <CrossProviderErrorAlert />
      ) : frameworks.length > 0 ? (
        <ComplianceFrameworkGrid>
          {frameworks.map((framework) => (
            <CrossProviderFrameworkCard
              key={framework.complianceId}
              {...framework}
            />
          ))}
        </ComplianceFrameworkGrid>
      ) : (
        <StatusPanel layout={STATUS_PANEL_LAYOUT.INLINE}>
          <StatusPanelIcon>
            <ShieldCheck />
          </StatusPanelIcon>
          <StatusPanelBody>
            <StatusPanelTitle>No AI frameworks installed</StatusPanelTitle>
            <StatusPanelDescription>
              Install OWASP Top 10 for LLMs, OWASP Agentic, OWASP MCP, NIST AI
              RMF, ISO 42001 or the EU AI Act from the Registry to measure your
              AI providers against them.
            </StatusPanelDescription>
          </StatusPanelBody>
          <StatusPanelActions>
            <Button asChild>
              <Link href={REGISTRY_COMPLIANCE_HREF}>Install from Registry</Link>
            </Button>
          </StatusPanelActions>
        </StatusPanel>
      )}
    </CardContent>
  </Card>
);
