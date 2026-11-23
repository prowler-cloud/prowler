import type { RealtimeSearchParams } from "@/app/(prowler)/realtime/_lib/routes";

/** What every dashboard tab receives from the page. */
export interface RealtimeTabProps {
  providerId: string;
  /** Sample data: the account has no policy yet. Writes are disabled. */
  demo: boolean;
  /** The role has `manage_prowler_realtime`. */
  canManage: boolean;
  searchParams: RealtimeSearchParams;
}
