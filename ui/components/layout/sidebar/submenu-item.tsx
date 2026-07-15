"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { useCloudUpgradeStore } from "@/store";
import {
  type MenuSelectionHandler,
  SUBMENU_KIND,
  type SubmenuProps,
} from "@/types";

type SubmenuItemProps = SubmenuProps & {
  onSelect?: MenuSelectionHandler;
};

export const SubmenuItem = (props: SubmenuItemProps) => {
  const pathname = usePathname();
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  if (props.kind === SUBMENU_KIND.CLOUD_UPGRADE) {
    const { cloudUpgradeFeature, icon: Icon, label, onSelect } = props;

    return (
      <Button
        type="button"
        variant="menu-inactive"
        className="mt-1 w-[calc(100%-12px)] justify-start px-2 py-1"
        onClick={() => {
          openCloudUpgrade(cloudUpgradeFeature, onSelect?.() ?? undefined);
        }}
      >
        <span className="mr-2">
          <Icon size={16} />
        </span>
        <span className="flex min-w-0 items-center gap-2">
          <span className="truncate">{label}</span>
          <Badge variant="cloud" size="sm">
            Cloud
          </Badge>
        </span>
      </Button>
    );
  }

  const {
    active,
    cloudOnly,
    disabled,
    highlight,
    href,
    icon: Icon,
    label,
    onSelect,
    target,
  } = props;
  const isActive = active !== undefined ? active : pathname === href;

  // Special case: Mutelist with tooltip when disabled
  if (disabled && label === "Mutelist") {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            className="pointer-events-none mt-1 w-[calc(100%-12px)] cursor-not-allowed justify-start px-2 py-1"
            disabled
          >
            <span className="mr-2">
              <Icon size={16} />
            </span>
            <p className="min-w-0 truncate">{label}</p>
          </Button>
        </TooltipTrigger>
        <TooltipContent side="right">
          The mutelist will be enabled after adding a provider
        </TooltipContent>
      </Tooltip>
    );
  }

  if (disabled) {
    const tooltip = cloudOnly
      ? "Available in Prowler Cloud"
      : `${label} is unavailable.`;

    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className="group mt-1 inline-flex w-[calc(100%-12px)]"
            tabIndex={0}
          >
            <Button
              variant="menu-inactive"
              className="text-text-neutral-tertiary w-full cursor-not-allowed justify-start px-2 py-1"
              aria-disabled="true"
              tabIndex={-1}
              type="button"
            >
              <span className="mr-2">
                <Icon size={16} />
              </span>
              <p className="flex min-w-0 items-center gap-2">
                <span className="truncate">{label}</span>
                {highlight && (
                  <Badge variant="new" size="sm">
                    New
                  </Badge>
                )}
              </p>
            </Button>
          </span>
        </TooltipTrigger>
        <TooltipContent side="right">{tooltip}</TooltipContent>
      </Tooltip>
    );
  }

  return (
    <Button
      variant={isActive ? "menu-active" : "menu-inactive"}
      className="mt-1 w-[calc(100%-12px)] justify-start px-2 py-1"
      asChild={!disabled}
      disabled={disabled}
    >
      <Link
        href={href}
        target={target}
        className="flex items-center"
        onClick={onSelect}
      >
        <span className="mr-2">
          <Icon size={16} />
        </span>
        <p className="flex min-w-0 items-center">
          <span className="truncate">{label}</span>
          {highlight && (
            <Badge variant="new" size="sm" className="ml-2">
              New
            </Badge>
          )}
        </p>
      </Link>
    </Button>
  );
};
