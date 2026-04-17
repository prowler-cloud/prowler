import { Icon } from "@iconify/react";

import { AuthCard } from "@/components/auth/oss/auth-card";
import { ProwlerShort } from "@/components/icons";
import { Button } from "@/components/shadcn";

const RELEASE = {
  version: "5.24.0",
  url: "https://github.com/prowler-cloud/prowler/releases/tag/5.24.0",
  repoUrl: "https://github.com/prowler-cloud/prowler",
} as const;

const HIGHLIGHTS: readonly string[] = [
  "Redesigned resources side drawer",
  "New AWS Bedrock & IAM hardening checks",
  "New Microsoft 365 Conditional Access coverage",
];

export const AuthReleaseHighlights = () => (
  <aside
    aria-label={`Prowler v${RELEASE.version} highlights`}
    className="hidden items-center justify-center px-6 py-10 sm:px-10 lg:flex"
  >
    <div className="w-full max-w-md">
      <AuthCard className="gap-6 px-7 py-8">
        <div
          aria-hidden="true"
          className="absolute top-6 right-6 flex h-9 w-9 items-center justify-center rounded-md bg-emerald-400/15"
        >
          <ProwlerShort width={18} className="text-emerald-400" />
        </div>

        <div className="pr-14">
          <p className="text-xs font-semibold text-emerald-400">
            Prowler v{RELEASE.version}
          </p>
          <h2 className="mt-1 text-2xl leading-tight font-semibold">
            Fresh off the branch
          </h2>
          <p className="text-default-500 mt-2 text-sm">
            A quick look at what we just shipped in v{RELEASE.version}.
          </p>
        </div>

        <ul className="flex flex-col gap-3">
          {HIGHLIGHTS.map((label) => (
            <li key={label} className="flex items-start gap-3">
              <Icon
                aria-hidden="true"
                icon="mdi:check-circle"
                width={20}
                className="mt-0.5 shrink-0 text-emerald-400"
              />
              <span className="text-sm">{label}</span>
            </li>
          ))}
        </ul>

        <div className="flex items-center justify-center gap-3">
          <Button asChild size="sm">
            <a href={RELEASE.url} target="_blank" rel="noopener noreferrer">
              See full release notes
            </a>
          </Button>
          <Button asChild variant="outline" size="sm">
            <a href={RELEASE.repoUrl} target="_blank" rel="noopener noreferrer">
              <Icon aria-hidden="true" icon="mdi:github" width={16} />
              GitHub
            </a>
          </Button>
        </div>
      </AuthCard>
    </div>
  </aside>
);
