export const RELEASE_COMPONENTS = ["UI", "API", "SDK"] as const;

export type ReleaseComponent = (typeof RELEASE_COMPONENTS)[number];

interface LatestReleaseBase {
  version: string;
  url: string;
  repoUrl: string;
}

export interface CuratedRelease extends LatestReleaseBase {
  kind: "curated";
  highlights: string[];
}

export interface PatchRelease extends LatestReleaseBase {
  kind: "patch";
  components: ReleaseComponent[];
}

export type LatestRelease = CuratedRelease | PatchRelease;
