/**
 * Runs async work over items with a fixed concurrency limit.
 *
 * Note: if `worker` throws, this function rejects. Callers should handle
 * expected per-item errors inside the worker and return a typed result.
 */
export async function runWithConcurrencyLimit<T, R>(
  items: T[],
  concurrencyLimit: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) {
    return [];
  }

  const normalizedConcurrency = Math.max(1, Math.floor(concurrencyLimit));
  const results = new Array<R>(items.length);
  let currentIndex = 0;

  const runWorker = async () => {
    while (currentIndex < items.length) {
      const assignedIndex = currentIndex;
      currentIndex += 1;
      results[assignedIndex] = await worker(
        items[assignedIndex],
        assignedIndex,
      );
    }
  };

  const workers = Array.from(
    { length: Math.min(normalizedConcurrency, items.length) },
    () => runWorker(),
  );

  await Promise.all(workers);
  return results;
}
