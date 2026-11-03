interface FindingsPreviewLockProps {
  totalCount?: number;
}

/** Cloudy never locks the findings list; kept as a no-op for call sites. */
export function FindingsPreviewLock(_props: FindingsPreviewLockProps) {
  return null;
}
