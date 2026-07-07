import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

// 1:1 skeleton of the panel chat empty state (logo, headline, composer,
// suggestion chips, recent chats). Kept in its own file with light imports:
// the side-panel shell uses it as the Suspense fallback while the real
// (lazy) chat bundle downloads, so it must not pull that bundle in.
export function LighthousePanelChatSkeleton() {
  return (
    <div
      aria-label="Loading Lighthouse AI"
      className="flex h-full min-h-0 flex-col items-center justify-center gap-5 overflow-hidden px-4 py-10"
    >
      {/* Lighthouse logo */}
      <Skeleton className="size-12 rounded-full" />

      {/* Headline + subline */}
      <div className="flex w-full flex-col items-center gap-2">
        <Skeleton className="h-5 w-3/5 max-w-72 rounded" />
        <Skeleton className="h-4 w-2/5 max-w-52 rounded" />
      </div>

      {/* Composer: textarea, then model selector + send button row */}
      <div className="border-border-neutral-secondary w-full max-w-4xl rounded-xl border p-3">
        <Skeleton className="h-10 w-full rounded" />
        <div className="mt-3 flex items-center justify-between gap-2">
          <Skeleton className="h-8 w-40 rounded-lg" />
          <Skeleton className="size-8 rounded-lg" />
        </div>
      </div>

      {/* "Try Lighthouse AI for..." suggestion chips */}
      <div className="flex w-full flex-col items-center gap-2">
        <Skeleton className="h-4 w-36 rounded" />
        <div className="flex w-full flex-wrap items-center justify-center gap-2">
          <Skeleton className="h-8 w-32 rounded-lg" />
          <Skeleton className="h-8 w-36 rounded-lg" />
          <Skeleton className="h-8 w-28 rounded-lg" />
          <Skeleton className="h-8 w-40 rounded-lg" />
        </div>
      </div>

      {/* Recent chats: label, search + new-chat row, session rows */}
      <div className="flex w-full max-w-4xl flex-col gap-2">
        <Skeleton className="h-4 w-24 rounded" />
        <div className="flex items-center gap-2">
          <Skeleton className="h-8 flex-1 rounded-lg" />
          <Skeleton className="size-8 shrink-0 rounded-lg" />
        </div>
        <div className="flex flex-col gap-1">
          <SessionRowSkeleton titleWidth="w-3/5" />
          <SessionRowSkeleton titleWidth="w-2/5" />
          <SessionRowSkeleton titleWidth="w-1/2" />
        </div>
      </div>
    </div>
  );
}

function SessionRowSkeleton({ titleWidth }: { titleWidth: string }) {
  return (
    <div className="flex items-center justify-between gap-2 px-2 py-2">
      <Skeleton className={`h-4 ${titleWidth} rounded`} />
      <Skeleton className="h-3 w-8 shrink-0 rounded" />
    </div>
  );
}
