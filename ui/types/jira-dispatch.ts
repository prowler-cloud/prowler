import type { JiraSelection } from "@/types/integrations";

export interface JiraDispatchModalPayload {
  selection: JiraSelection;
  findingTitle?: string;
  selectedResourceCount?: number;
  isFindingGroupSelection?: boolean;
  description?: string;
}
