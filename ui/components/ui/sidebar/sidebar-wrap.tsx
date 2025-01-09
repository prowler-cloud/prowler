"use client";

import { Icon } from "@iconify/react";
import { Button, ScrollShadow, Spacer, Tooltip } from "@nextui-org/react";
import clsx from "clsx";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useSession } from "next-auth/react";
import React, { Suspense, useCallback } from "react";
import { useMediaQuery } from "usehooks-ts";

import { logOut } from "@/actions/auth";
import { AddIcon } from "@/components/icons";
import { useUIStore } from "@/store";

import {
  ProwlerExtended,
  ProwlerShort,
} from "../../icons/prowler/ProwlerIcons";
import { ThemeSwitch } from "../../ThemeSwitch";
import { CustomButton } from "../custom";
import Sidebar from "./sidebar";
import { sectionItemsWithTeams } from "./sidebar-items";
import { UserAvatar } from "./user-avatar";

export const SidebarWrap = () => {
  const pathname = usePathname();
  const { data: session } = useSession();

  const isCollapsed = useUIStore((state) => state.isSideMenuOpen);
  const openSideMenu = useUIStore((state) => state.openSideMenu);
  const closeSideMenu = useUIStore((state) => state.closeSideMenu);

  const isMobile = useMediaQuery("(max-width: 768px)");
  const isCompact = isCollapsed || isMobile;

  const onToggle = useCallback(() => {
    if (!isCollapsed) openSideMenu();
    if (isCollapsed) closeSideMenu();
  }, [isCollapsed]);

  const currentPath = pathname === "/" ? "overview" : pathname.split("/")?.[1];

  return (
    <div
      className={clsx(
        "relative flex h-screen flex-col rounded-r-3xl !border-r-small border-divider transition-width",
        {
          "w-72 p-6": !isCompact,
          "w-16 items-center px-2 py-6": isCompact,
        },
      )}
    >
      <div className="flex flex-col gap-y-8">
        <Link
          href="/"
          className={clsx(
            "flex w-full flex-col items-center justify-center gap-y-8 px-3",
            {
              "gap-0": isCompact,
            },
          )}
        >
          <div
            className={clsx({
              hidden: !isCompact,
            })}
          >
            <ProwlerShort />
          </div>
          <div
            className={clsx({
              hidden: isCompact,
              "!mt-0": !isCompact,
            })}
          >
            <ProwlerExtended />
          </div>
        </Link>
        <Link href={"/users"}>
          <Suspense fallback={<p>Loading...</p>}>
            <UserAvatar
              userName={session?.user.name ?? "Guest"}
              position={session?.user.companyName ?? "Company Name"}
              isCompact={isCompact}
            />
          </Suspense>
        </Link>
        <div
          className={clsx({
            hidden: isCompact,
            "w-full": !isCompact,
          })}
        >
          <CustomButton
            asLink="/scans"
            className="w-full"
            ariaLabel="Launch Scan"
            variant="solid"
            color="action"
            size="md"
            endContent={<AddIcon size={20} />}
          >
            Launch Scan
          </CustomButton>
        </div>
      </div>

      <ScrollShadow hideScrollBar className="-mr-6 h-full max-h-full py-4 pr-6">
        <Sidebar
          defaultSelectedKey="overview"
          isCompact={isCompact}
          items={sectionItemsWithTeams}
          selectedKeys={[currentPath]}
        />
      </ScrollShadow>
      <Spacer y={2} />
      <div
        className={clsx("mt-auto flex flex-col", {
          "items-center": isCompact,
        })}
      >
        <Tooltip
          content="Documentation"
          isDisabled={!isCompact}
          placement="right"
        >
          <CustomButton
            asLink="https://docs.prowler.com/"
            target="_blank"
            ariaLabel="Documentation"
            variant="flat"
            className={clsx(
              "justify-start truncate bg-transparent text-default-500 data-[hover=true]:text-foreground dark:bg-transparent",
              {
                "justify-center": isCompact,
              },
            )}
            isIconOnly={isCompact}
            startContent={
              isCompact ? null : (
                <Icon
                  className="flex-none text-default-500"
                  icon="tabler:file-type-doc"
                  width={24}
                  aria-hidden="true"
                />
              )
            }
          >
            {isCompact ? (
              <Icon
                className="text-default-500"
                icon="tabler:file-type-doc"
                width={24}
                aria-hidden="true"
              />
            ) : (
              "Documentation"
            )}
          </CustomButton>
        </Tooltip>
        <Tooltip
          content="API reference"
          isDisabled={!isCompact}
          placement="right"
        >
          <CustomButton
            asLink={
              process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true"
                ? "https://api.prowler.com/api/v1/docs"
                : `${process.env.NEXT_PUBLIC_API_DOCS_URL}`
            }
            target="_blank"
            ariaLabel="API reference"
            variant="flat"
            className={clsx(
              "justify-start truncate bg-transparent text-default-500 data-[hover=true]:text-foreground dark:bg-transparent",
              {
                "justify-center": isCompact,
              },
            )}
            isIconOnly={isCompact}
            startContent={
              isCompact ? null : (
                <Icon
                  className="flex-none text-default-500"
                  icon="tabler:api"
                  width={24}
                  aria-hidden="true"
                />
              )
            }
          >
            {isCompact ? (
              <Icon
                className="text-default-500"
                icon="tabler:api"
                width={24}
                aria-hidden="true"
              />
            ) : (
              "API reference"
            )}
          </CustomButton>
        </Tooltip>

        <Tooltip content="Support" isDisabled={!isCompact} placement="right">
          <CustomButton
            asLink="https://github.com/prowler-cloud/prowler/issues"
            target="_blank"
            ariaLabel="Support"
            variant="flat"
            className={clsx(
              "justify-start truncate bg-transparent text-default-500 data-[hover=true]:text-foreground dark:bg-transparent",
              {
                "justify-center": isCompact,
              },
            )}
            isIconOnly={isCompact}
            startContent={
              isCompact ? null : (
                <Icon
                  className="flex-none text-default-500"
                  icon="akar-icons:info"
                  width={24}
                  aria-hidden="true"
                />
              )
            }
          >
            {isCompact ? (
              <Icon
                className="text-default-500"
                icon="akar-icons:info"
                width={24}
                aria-hidden="true"
              />
            ) : (
              "Support"
            )}
          </CustomButton>
        </Tooltip>
        {/* <Tooltip
      content="Product Updates"
      isDisabled={!isCompact}
      placement="right"
    >
      <Button
        aria-label="Product Updates"
        className={clsx(
          "justify-start text-default-500 data-[hover=true]:text-foreground",
          {
            "justify-center": isCompact,
          },
        )}
        isIconOnly={isCompact}
        startContent={
          isCompact ? null : (
            <Icon
              className="flex-none text-default-500"
              icon="mdi:update"
              width={24}
              aria-hidden="true"
            />
          )
        }
        variant="light"
      >
        {isCompact ? (
          <Icon
            className="text-default-500"
            icon="mdi:update"
            width={24}
            aria-hidden="true"
          />
        ) : (
          "Product Updates"
        )}
      </Button>
    </Tooltip> */}

        <Tooltip content="Log Out" isDisabled={!isCompact} placement="right">
          <Button
            aria-label="Log Out"
            onClick={() => logOut()}
            className={clsx(
              "justify-start text-default-500 data-[hover=true]:text-foreground",
              {
                "justify-center": isCompact,
              },
            )}
            isIconOnly={isCompact}
            startContent={
              isCompact ? null : (
                <Icon
                  className="flex-none text-default-500"
                  icon="heroicons-outline:logout"
                  width={24}
                  aria-hidden="true"
                />
              )
            }
            variant="light"
          >
            {isCompact ? (
              <Icon
                className="text-default-500"
                icon="heroicons-outline:logout"
                width={24}
                aria-hidden="true"
              />
            ) : (
              "Log Out"
            )}
          </Button>
        </Tooltip>
      </div>
      <div
        className={clsx("mt-auto flex justify-end gap-3", {
          "flex-col items-center": isCompact,
          "items-baseline": !isCompact,
        })}
      >
        <Tooltip
          content="Light | Dark mode"
          placement={isCompact ? "right" : "top"}
        >
          <div
            className={clsx(
              "px-0 text-default-500 data-[hover=true]:text-foreground",
              {
                "mt-3 justify-center": isCompact,
              },
            )}
          >
            <ThemeSwitch aria-label="Toggle theme" />
          </div>
        </Tooltip>
        <Tooltip
          content="Open | Close sidebar"
          placement={isCompact ? "right" : "top"}
        >
          <Button
            aria-label={isCompact ? "Open sidebar" : "Close sidebar"}
            className={clsx(
              "px-0 text-default-500 data-[hover=true]:text-foreground",
              {
                "justify-center": isCompact,
              },
            )}
            isIconOnly
            size="sm"
            variant="light"
            onPress={onToggle}
          >
            <Icon
              className="text-default-500"
              height={24}
              icon="solar:sidebar-minimalistic-outline"
              width={24}
              aria-hidden="true"
            />
          </Button>
        </Tooltip>
      </div>
    </div>
  );
};
