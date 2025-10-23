"use client";

import { CheckIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
} from "@/components/icons/providers-badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import type { ProviderProps, ProviderType } from "@/types/providers";

const PROVIDER_ICON: Record<ProviderType, React.ReactNode> = {
  aws: <AWSProviderBadge width={18} height={18} />,
  azure: <AzureProviderBadge width={18} height={18} />,
  gcp: <GCPProviderBadge width={18} height={18} />,
  kubernetes: <KS8ProviderBadge width={18} height={18} />,
  m365: <M365ProviderBadge width={18} height={18} />,
  github: <GitHubProviderBadge width={18} height={18} />,
};

interface AccountsSelectorProps {
  providers: ProviderProps[];
}

export function AccountsSelector({ providers }: AccountsSelectorProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [open, setOpen] = useState(false);

  const current = searchParams.get("filter[provider_id__in]") || "";
  const selectedType = (searchParams.get("filter[provider_type]") || "") as
    | ProviderType
    | "";
  const selectedIds = current ? current.split(",").filter(Boolean) : [];
  const visibleProviders = providers
    .filter((p) => p.attributes.connection?.connected)
    .filter((p) =>
      selectedType ? p.attributes.provider === selectedType : true,
    );

  const updateQuery = (ids: string[]) => {
    const params = new URLSearchParams(searchParams.toString());
    if (ids.length > 0) {
      params.set("filter[provider_id__in]", ids.join(","));
    } else {
      params.delete("filter[provider_id__in]");
    }
    router.push(`?${params.toString()}`, { scroll: false });
  };

  const toggleId = (id: string) => {
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    updateQuery(Array.from(next));
  };

  const selectedLabel = () => {
    if (selectedIds.length === 0) return null; // placeholder visible
    if (selectedIds.length === 1) {
      const p = providers.find((pr) => pr.id === selectedIds[0]);
      const name = p ? p.attributes.alias || p.attributes.uid : selectedIds[0];
      return <span className="truncate">{name}</span>;
    }
    return (
      <span className="truncate">{selectedIds.length} accounts selected</span>
    );
  };

  return (
    <Select
      open={open}
      onOpenChange={setOpen}
      value=""
      onValueChange={() => {}}
    >
      <SelectTrigger>
        <SelectValue placeholder="All accounts">{selectedLabel()}</SelectValue>
      </SelectTrigger>
      <SelectContent align="start">
        {visibleProviders.map((p) => {
          const id = p.id;
          const displayName = p.attributes.alias || p.attributes.uid;
          const isSelected = selectedIds.includes(id);
          const icon = PROVIDER_ICON[p.attributes.provider as ProviderType];
          return (
            <SelectItem
              key={id}
              value={id}
              // Toggle selection without closing or changing radix value
              onPointerDown={(e) => {
                e.preventDefault();
                toggleId(id);
              }}
              className={isSelected ? "bg-slate-100 dark:bg-slate-700/50" : ""}
            >
              <span className="flex w-full items-center justify-between gap-3">
                <span className="flex min-w-0 items-center gap-2">
                  {icon}
                  <span className="truncate">{displayName}</span>
                </span>
                {isSelected && <CheckIcon className="size-5 text-white" />}
              </span>
            </SelectItem>
          );
        })}
      </SelectContent>
    </Select>
  );
}
