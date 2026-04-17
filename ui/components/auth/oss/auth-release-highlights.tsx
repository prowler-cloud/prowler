import { Icon } from "@iconify/react";

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
    className="hidden w-full max-w-md lg:block"
  >
    <div className="relative overflow-hidden rounded-3xl border border-black/8 bg-gradient-to-br from-white/78 via-white/70 to-white/58 p-8 shadow-2xl ring-1 shadow-slate-300/35 ring-white/55 backdrop-blur-2xl dark:border-white/10 dark:from-black/70 dark:via-black/62 dark:to-black/52 dark:shadow-black/45 dark:ring-white/6">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-gradient-to-br from-white/55 via-white/10 to-transparent dark:from-white/8 dark:via-transparent"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-18 -right-12 h-40 w-40 rounded-full bg-emerald-400/8 blur-3xl dark:bg-emerald-400/8"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -bottom-16 left-8 h-28 w-28 rounded-full bg-cyan-400/8 blur-3xl dark:bg-cyan-400/6"
      />

      <div className="relative flex flex-col gap-6">
        <div
          aria-hidden="true"
          className="flex h-10 w-10 items-center justify-center rounded-xl border border-black/8 bg-emerald-400/18 shadow-lg shadow-emerald-400/15 dark:border-white/10 dark:bg-emerald-400/15 dark:shadow-emerald-950/30"
        >
          <ProwlerShort width={18} className="text-emerald-400" />
        </div>

        <div>
          <p className="text-xs font-semibold tracking-wide text-emerald-700 uppercase dark:text-emerald-300">
            Prowler v{RELEASE.version}
          </p>
          <h2 className="mt-1 text-2xl leading-tight font-semibold text-slate-950 dark:text-white dark:drop-shadow-sm">
            Fresh off the branch
          </h2>
          <p className="mt-2 max-w-sm text-sm text-slate-600 dark:text-white/72">
            A quick look at what we just shipped in v{RELEASE.version}.
          </p>
        </div>

        <ul className="flex flex-col gap-3">
          {HIGHLIGHTS.map((label) => (
            <li
              key={label}
              className="flex items-start gap-3 text-slate-700 dark:text-white/90"
            >
              <Icon
                aria-hidden="true"
                icon="mdi:check-circle"
                width={20}
                className="mt-0.5 shrink-0 text-emerald-600 drop-shadow-sm dark:text-emerald-300"
              />
              <span className="text-sm leading-6">{label}</span>
            </li>
          ))}
        </ul>

        <div className="flex items-center gap-3">
          <Button asChild size="sm" className="shadow-lg shadow-emerald-950/25">
            <a href={RELEASE.url} target="_blank" rel="noopener noreferrer">
              See full release notes
            </a>
          </Button>
          <Button
            asChild
            variant="outline"
            size="sm"
            className="border-black/8 bg-white/45 text-slate-900 hover:bg-white/70 dark:border-white/12 dark:bg-white/6 dark:text-white dark:hover:bg-white/10"
          >
            <a href={RELEASE.repoUrl} target="_blank" rel="noopener noreferrer">
              <Icon aria-hidden="true" icon="mdi:github" width={16} />
              GitHub
            </a>
          </Button>
        </div>
      </div>
    </div>
  </aside>
);
