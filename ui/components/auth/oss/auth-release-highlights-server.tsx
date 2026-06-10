import { getLatestRelease } from "@/actions/releases/releases";
import { AuthReleaseHighlights } from "@/components/auth/oss/auth-release-highlights";

export const AuthReleaseHighlightsServer = async () => {
  const release = await getLatestRelease();
  if (!release) return null;
  return <AuthReleaseHighlights release={release} />;
};
