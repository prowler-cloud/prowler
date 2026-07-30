"use client";

import { Dispatch, SetStateAction, useState } from "react";

import {
  deleteOrganization,
  deleteOrganizationNode,
} from "@/actions/organizations/organizations";
import { DeleteIcon } from "@/components/icons";
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
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}

export function DeleteOrganizationForm({
  id,
  name,
  variant,
  orgType,
  kind,
  setIsOpen,
}: DeleteOrganizationFormProps) {
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  const isOrg = variant === PROVIDERS_GROUP_KIND.ORGANIZATION;
  const entityLabel = isOrg
    ? "organization"
    : getNodeLabel(orgType, kind).toLowerCase();

  const handleDelete = async () => {
    setIsLoading(true);

    const result = isOrg
      ? await deleteOrganization(id)
      : await deleteOrganizationNode(id);

    setIsLoading(false);

    if (result?.errors && result.errors.length > 0) {
      const error = result.errors[0];
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: `${error.detail}`,
      });
    } else if (result?.error) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: result.error,
      });
    } else {
      toast({
        title: "Success!",
        description: `The ${entityLabel} "${name}" was removed successfully.`,
      });
      setIsOpen(false);
    }
  };

  return (
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
  );
}
