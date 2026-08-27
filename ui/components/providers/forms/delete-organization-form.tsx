"use client";

import { useRouter } from "next/navigation";
import { Dispatch, SetStateAction, useState } from "react";

import {
  deleteOrganization,
  deleteOrganizationNode,
} from "@/actions/organizations/organizations";
import { DeleteIcon } from "@/components/icons";
import { pollTaskCompletion } from "@/components/providers/organizations/org-account-selection.utils";
import { Button, useToast } from "@/components/shadcn";
import { getNodeLabel } from "@/lib/organizations";
import { NodeKind, OrganizationType } from "@/types/organizations";
import {
  PROVIDERS_GROUP_KIND,
  ProvidersGroupKind,
} from "@/types/providers-table";

interface DeleteOrganizationFormProps {
  id: string;
  name: string;
  variant: ProvidersGroupKind;
  orgType: OrganizationType;
  kind?: NodeKind;
  /** Providers that cascade-delete with this entity. */
  providerCount: number;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}

function extractTaskId(result: unknown): string | null {
  if (
    result &&
    typeof result === "object" &&
    "data" in result &&
    result.data &&
    typeof result.data === "object" &&
    "id" in result.data &&
    typeof (result.data as { id: unknown }).id === "string"
  ) {
    return (result.data as { id: string }).id;
  }
  return null;
}

export function DeleteOrganizationForm({
  id,
  name,
  variant,
  orgType,
  kind,
  providerCount,
  setIsOpen,
}: DeleteOrganizationFormProps) {
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();
  const router = useRouter();

  const isOrg = variant === PROVIDERS_GROUP_KIND.ORGANIZATION;
  const entityLabel = isOrg
    ? "organization"
    : getNodeLabel(orgType, kind).toLowerCase();

  const handleDelete = async () => {
    setIsLoading(true);

    const result = isOrg
      ? await deleteOrganization(id)
      : await deleteOrganizationNode(id);

    if (result?.errors?.length || result?.error) {
      setIsLoading(false);
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: result.errors?.[0]?.detail ?? result.error,
      });
      return;
    }

    // The task completes once the per-provider deletions are *dispatched*, and any
    // rollback runs in an errback task with no id to poll — so a completed task
    // means "accepted", never "done". Both outcomes refetch, because a rollback
    // restores the subtree and its rows have to reappear.
    const taskId = extractTaskId(result);
    const taskResult = taskId
      ? await pollTaskCompletion(taskId)
      : { success: true as const };

    setIsLoading(false);

    if (!taskResult.success) {
      toast({
        variant: "destructive",
        title: "Deletion did not complete",
        description:
          taskResult.error ??
          `The ${entityLabel} "${name}" could not be deleted.`,
      });
      setIsOpen(false);
      router.refresh();
      return;
    }

    toast({
      title: "Deletion started",
      description: `Prowler is deleting the ${entityLabel} "${name}" and its providers. If any part of it fails, the rows reappear on a later refresh.`,
    });
    setIsOpen(false);
    router.refresh();
  };

  return (
    <div className="flex flex-col gap-4">
      {providerCount > 0 && (
        <p className="text-text-neutral-secondary text-sm">
          This will also delete{" "}
          <strong>
            {providerCount} {providerCount === 1 ? "provider" : "providers"}
          </strong>{" "}
          grouped under this {entityLabel}.
        </p>
      )}

      <div className="flex w-full justify-end gap-4">
        <Button
          type="button"
          variant="ghost"
          size="lg"
          onClick={() => setIsOpen(false)}
          disabled={isLoading}
        >
          Cancel
        </Button>

        <Button
          type="button"
          variant="destructive"
          size="lg"
          disabled={isLoading}
          onClick={handleDelete}
        >
          {!isLoading && <DeleteIcon size={24} />}
          {isLoading ? "Loading" : "Delete"}
        </Button>
      </div>
    </div>
  );
}
