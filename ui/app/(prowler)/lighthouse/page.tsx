import { getLighthouseConfig } from "@/actions/lighthouse/lighthouse";
import { Chat } from "@/components/lighthouse";
import { ContentLayout } from "@/components/ui";
import { CacheService } from "@/lib/lighthouse/cache";
import { suggestedActions } from "@/lib/lighthouse/suggested-actions";

interface LighthousePageProps {
  searchParams: { cachedMessage?: string };
}

export default async function AIChatbot({ searchParams }: LighthousePageProps) {
  const config = await getLighthouseConfig();

  const hasConfig = !!config;
  const isActive = config?.attributes?.is_active ?? false;

  // Fetch cached content if a cached message type is specified
  let cachedContent = null;
  if (searchParams.cachedMessage) {
    const cached = await CacheService.getCachedMessage(
      searchParams.cachedMessage,
    );
    cachedContent = cached.success ? cached.data : null;
  }

  // Pre-fetch all question answers and processing status
  const isProcessing = await CacheService.isRecommendationProcessing();
  const questionAnswers: Record<string, string> = {};

  if (!isProcessing) {
    for (const action of suggestedActions) {
      if (action.questionRef) {
        const cached = await CacheService.getCachedMessage(
          `question_${action.questionRef}`,
        );
        if (cached.success && cached.data) {
          questionAnswers[action.questionRef] = cached.data;
        }
      }
    }
  }

  return (
    <ContentLayout title="Lighthouse" icon="lucide:bot">
      <Chat
        hasConfig={hasConfig}
        isActive={isActive}
        cachedContent={cachedContent}
        messageType={searchParams.cachedMessage}
        isProcessing={isProcessing}
        questionAnswers={questionAnswers}
      />
    </ContentLayout>
  );
}
