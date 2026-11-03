import { SamplePreviewBanner } from "@/components/shared/sample-preview/sample-preview-banner";
import { getSamplePreviewState } from "@/lib/sample-preview/get-sample-preview-state";
import { SAMPLE_ATTACK_PATHS } from "@/lib/sample-preview/sample-attack-paths";
import { SAMPLE_PREVIEW_PAGE } from "@/lib/sample-preview/sample-preview-events";

import AttackPathsPage from "./(workflow)/query-builder/attack-paths-page";

export default async function AttackPathsRoute() {
  // Decided on the server, so the sample never flashes in after the real page.
  const samplePreview = await getSamplePreviewState();
  if (!samplePreview.active) return <AttackPathsPage />;

  return (
    <>
      <SamplePreviewBanner
        state={samplePreview}
        page={SAMPLE_PREVIEW_PAGE.ATTACK_PATHS}
      />
      <AttackPathsPage sample={SAMPLE_ATTACK_PATHS} />
    </>
  );
}
