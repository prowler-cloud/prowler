"use server";

import { unstable_cache } from "next/cache";
import { z } from "zod";

import type { LatestRelease, ReleaseComponent } from "./types";
import { RELEASE_COMPONENTS } from "./types";

const REPO = "prowler-cloud/prowler";
const REPO_URL = `https://github.com/${REPO}`;
const RELEASES_ENDPOINT = `https://api.github.com/repos/${REPO}/releases?per_page=10`;
const MAX_HIGHLIGHTS = 3;
const MAX_CONTRIBUTORS = 8;
const REVALIDATE_SECONDS = 3600;

const META_HEADINGS = [
  /^what'?s changed$/i,
  /^new contributors$/i,
  /^community contributors$/i,
  /^contributors$/i,
  /^full changelog$/i,
];

const CONTRIBUTOR_HEADING = /contributor/i;
const CONTRIBUTOR_HANDLE = /(?:^|[\s([])@([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/g;

const releaseSchema = z.object({
  tag_name: z.string(),
  html_url: z.url(),
  body: z.string().nullable(),
  draft: z.boolean(),
  prerelease: z.boolean(),
});

const releaseListSchema = z.array(releaseSchema);

const stripLeadingSymbols = (s: string) =>
  s.replace(/^[^A-Za-z0-9]+/, "").trim();

const startsWithNonAscii = (s: string) => {
  const first = s.trim().charCodeAt(0);
  return Number.isFinite(first) && first > 127;
};

const stripFencedAndDetails = (body: string) =>
  body
    .replace(/```[\s\S]*?```/g, "")
    .replace(/<details[\s\S]*?<\/details>/gi, "");

const parseContributors = (clean: string): string[] => {
  const sectionRe = /^##\s+(.+?)\s*$/gm;
  const matches = Array.from(clean.matchAll(sectionRe));
  const seen = new Set<string>();
  const ordered: string[] = [];

  for (let i = 0; i < matches.length; i++) {
    const heading = matches[i][1].trim();
    if (!CONTRIBUTOR_HEADING.test(stripLeadingSymbols(heading))) continue;

    const start = matches[i].index! + matches[i][0].length;
    const end = matches[i + 1]?.index ?? clean.length;
    const section = clean.slice(start, end);

    for (const m of Array.from(section.matchAll(CONTRIBUTOR_HANDLE))) {
      const handle = m[1];
      if (seen.has(handle.toLowerCase())) continue;
      seen.add(handle.toLowerCase());
      ordered.push(handle);
      if (ordered.length >= MAX_CONTRIBUTORS) return ordered;
    }
  }

  return ordered;
};

const parseBody = (
  body: string,
): {
  curated: string[];
  components: ReleaseComponent[];
  contributors: string[];
} => {
  const clean = stripFencedAndDetails(body);
  const headings = Array.from(clean.matchAll(/^##\s+(.+?)\s*$/gm)).map((m) =>
    m[1].trim(),
  );

  const curated = headings
    .filter(startsWithNonAscii)
    .filter((h) => !META_HEADINGS.some((re) => re.test(stripLeadingSymbols(h))))
    .slice(0, MAX_HIGHLIGHTS);

  const components: ReleaseComponent[] = RELEASE_COMPONENTS.filter((comp) =>
    headings.some((h) => h.toUpperCase() === comp),
  );

  const contributors = parseContributors(clean);

  return { curated, components, contributors };
};

const buildHeaders = (): HeadersInit => {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  return headers;
};

const fetchLatestReleaseWithHighlights = async (): Promise<LatestRelease> => {
  const res = await fetch(RELEASES_ENDPOINT, {
    headers: buildHeaders(),
    next: { revalidate: REVALIDATE_SECONDS },
  });

  if (!res.ok) {
    throw new Error(`GitHub releases API responded with ${res.status}`);
  }

  const json = await res.json();
  const releases = releaseListSchema.parse(json);

  for (const release of releases) {
    if (release.draft || release.prerelease || !release.body) continue;
    const { curated, components, contributors } = parseBody(release.body);

    const base = {
      version: release.tag_name.replace(/^v/, ""),
      url: release.html_url,
      repoUrl: REPO_URL,
      contributors,
    };

    if (curated.length > 0) {
      return { ...base, kind: "curated", highlights: curated };
    }
    if (components.length > 0) {
      return { ...base, kind: "patch", components };
    }
  }

  throw new Error("No releases with parseable highlights or components");
};

const getCachedLatestRelease = unstable_cache(
  fetchLatestReleaseWithHighlights,
  ["github-latest-release", REPO],
  {
    revalidate: REVALIDATE_SECONDS,
    tags: ["releases"],
  },
);

export async function getLatestRelease(): Promise<LatestRelease | null> {
  try {
    return await getCachedLatestRelease();
  } catch (err) {
    console.error("[releases] failed to resolve latest release:", err);
    return null;
  }
}
