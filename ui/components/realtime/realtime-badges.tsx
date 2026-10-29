import { Badge } from "@/components/shadcn/badge/badge";
import {
  actionStatusBadge,
  type BadgeDescriptor,
  dataStoreBadge,
  detectionStatusBadge,
  feedStatusBadge,
  routeBadge,
} from "@/lib/realtime/display";

const render = ({ label, tone }: BadgeDescriptor) => (
  <Badge variant={tone}>{label}</Badge>
);

export const ActionStatusBadge = ({ status }: { status: string }) =>
  render(actionStatusBadge(status));

export const DetectionStatusBadge = ({ status }: { status: string }) =>
  render(detectionStatusBadge(status));

export const RouteBadge = ({ route }: { route: string }) =>
  render(routeBadge(route));

export const FeedStatusBadge = ({ status }: { status: string }) =>
  render(feedStatusBadge(status));

export const DataStoreBadge = ({ state }: { state: string }) =>
  render(dataStoreBadge(state));
