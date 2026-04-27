import { Tooltip } from "@heroui/tooltip";
import { Icon } from "@iconify/react";

import type { LatestRelease, ReleaseComponent } from "@/actions/releases/types";
import { ProwlerShort } from "@/components/icons";
import { Button } from "@/components/shadcn";

interface AuthReleaseHighlightsProps {
  release: LatestRelease;
}

const formatPatchMessage = (components: ReleaseComponent[]): string => {
  const [a, b, c] = components;
  if (!a) return "";
  if (!b) return `This version contains multiple fixes on the ${a} component.`;
  if (!c) {
    return `This version contains multiple fixes across ${a} and ${b} components.`;
  }
  return `This version contains multiple fixes across ${a}, ${b} and ${c} components.`;
};

export const AuthReleaseHighlights = ({
  release,
}: AuthReleaseHighlightsProps) => (
  <aside
    aria-label={
      release.kind === "curated"
        ? `Prowler v${release.version} release highlights`
        : `Prowler v${release.version} patch summary`
    }
    className="hidden w-full max-w-md lg:block"
  >
    <div className="relative min-h-[380px] overflow-hidden rounded-3xl border border-black/8 bg-gradient-to-br from-white/78 via-white/70 to-white/58 p-8 shadow-2xl ring-1 shadow-slate-300/35 ring-white/55 backdrop-blur-2xl dark:border-white/10 dark:from-black/82 dark:via-black/74 dark:to-black/68 dark:shadow-black/45 dark:ring-white/6">
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
          <ProwlerShort
            width={18}
            className="text-emerald-700 dark:text-emerald-300"
          />
        </div>

        <div>
          <p className="text-xs font-semibold tracking-wide text-emerald-700 uppercase dark:text-emerald-200">
            Prowler v{release.version}
          </p>
          <h2 className="mt-1 text-2xl leading-tight font-semibold text-slate-950 dark:text-white dark:drop-shadow-sm">
            Fresh off the branch
          </h2>
          <p className="mt-2 max-w-sm text-sm text-slate-600 dark:text-white/85">
            A quick look at what we just shipped in v{release.version}.
          </p>
        </div>

        {release.kind === "curated" && (
          <ul className="flex flex-col gap-3">
            {release.highlights.map((label) => (
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
        )}

        {release.kind === "patch" && (
          <p className="text-sm leading-6 text-slate-700 dark:text-white/90">
            {formatPatchMessage(release.components)}
          </p>
        )}

        {release.contributors.length > 0 && (
          <div className="flex flex-col gap-2">
            <p className="text-xs font-semibold tracking-wide text-slate-600 uppercase dark:text-white/70">
              Community contributors
            </p>
            <ul className="flex flex-wrap items-center">
              {release.contributors.map((handle) => (
                <li key={handle} className="-ml-2 first:ml-0">
                  <Tooltip content={`@${handle}`} placement="top" shadow="sm">
                    <a
                      href={`https://github.com/${handle}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      aria-label={`@${handle} on GitHub`}
                      className="block rounded-full ring-2 ring-white/80 transition-transform hover:z-10 hover:scale-110 focus-visible:z-10 focus-visible:ring-emerald-400/80 focus-visible:outline-none dark:ring-black/60"
                    >
                      <img
                        src={`https://github.com/${handle}.png?size=80`}
                        alt=""
                        width={32}
                        height={32}
                        loading="lazy"
                        className="h-8 w-8 rounded-full bg-slate-200 object-cover dark:bg-white/10"
                      />
                    </a>
                  </Tooltip>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-4">
          <Button
            asChild
            variant="outline"
            size="sm"
            className="border-black/8 bg-white/45 text-slate-900 hover:bg-white/70 dark:border-white/12 dark:bg-white/6 dark:text-white dark:hover:bg-white/10"
          >
            <a href={release.repoUrl} target="_blank" rel="noopener noreferrer">
              <Icon aria-hidden="true" icon="mdi:github" width={16} />
              GitHub
            </a>
          </Button>
          <a
            href={release.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded-sm text-sm font-medium text-emerald-700 transition-colors hover:text-emerald-800 focus-visible:ring-2 focus-visible:ring-emerald-400/60 focus-visible:outline-none dark:text-emerald-200 dark:hover:text-emerald-100"
          >
            See full release notes
            <Icon aria-hidden="true" icon="mdi:arrow-top-right" width={16} />
          </a>
        </div>
      </div>
    </div>
  </aside>
);
