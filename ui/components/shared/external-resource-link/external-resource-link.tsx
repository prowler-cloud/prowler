import { ExternalLink } from "lucide-react";

import { Button } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { buildAwsConsoleUrl } from "@/lib/aws-utils";
import { buildGitFileUrl, extractLineRangeFromUid } from "@/lib/iac-utils";

interface ExternalResourceLinkProps {
  providerType: string | null | undefined;
  resourceUid?: string | null;
  providerUid?: string | null;
  resourceName?: string | null;
  findingUid?: string | null;
  region?: string | null;
  className?: string;
}

interface ExternalResourceTarget {
  url: string;
  label: string;
  tooltip: string;
}

export const resolveExternalTarget = ({
  providerType,
  resourceUid,
  providerUid,
  resourceName,
  findingUid,
  region,
}: ExternalResourceLinkProps): ExternalResourceTarget | null => {
  if (providerType === "aws" && resourceUid) {
    const url = buildAwsConsoleUrl(resourceUid);
    if (!url) return null;
    return {
      url,
      label: "View in AWS Console",
      tooltip: "Open resource in AWS Console",
    };
  }

  if (providerType === "iac" && providerUid && resourceName) {
    const lineRange = findingUid
      ? (extractLineRangeFromUid(findingUid) ?? "")
      : "";
    const url = buildGitFileUrl(
      providerUid,
      resourceName,
      lineRange,
      region ?? undefined,
    );
    if (!url) return null;
    return {
      url,
      label: "View in Repository",
      tooltip: "Open resource in the repository",
    };
  }

  return null;
};

export const ExternalResourceLink = (props: ExternalResourceLinkProps) => {
  const target = resolveExternalTarget(props);
  if (!target) return null;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="link"
          size="link-xs"
          asChild
          className={props.className}
        >
          <a
            href={target.url}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={target.tooltip}
          >
            {target.label}
            <ExternalLink className="size-3" />
          </a>
        </Button>
      </TooltipTrigger>
      <TooltipContent>{target.tooltip}</TooltipContent>
    </Tooltip>
  );
};
