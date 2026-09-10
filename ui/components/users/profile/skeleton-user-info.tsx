import {
  Card,
  CardAction,
  CardContent,
  CardHeader,
  Separator,
  Skeleton,
} from "@/components/shadcn";

// Mirrors the real profile layout: one large card with sections stacked
// vertically. Conditional cards (SAML / API keys) depend on permissions not
// known while loading, so we mirror only the always-present structure.
export const SkeletonUserInfo = () => {
  return (
    <Card
      variant="base"
      padding="none"
      role="region"
      aria-label="User profile settings loading"
      className="w-full gap-4 p-4 md:p-5"
    >
      <UserBasicInfoSkeleton />
      <RolesCardSkeleton />
      <OrganizationsCardSkeleton />
    </Card>
  );
};

const UserBasicInfoSkeleton = () => {
  return (
    <Card variant="inner" padding="none" className="p-4 md:p-5">
      <CardContent>
        {/* Avatar + name / email */}
        <div className="flex items-center gap-4">
          <Skeleton className="size-10 rounded-full" />
          <div className="flex flex-col gap-1.5">
            <Skeleton className="h-4 w-32 rounded" />
            <Skeleton className="h-3 w-48 rounded" />
          </div>
        </div>
        <Separator className="my-4" />
        {/* Date Joined + Organization ID */}
        <div className="flex flex-row gap-4 md:gap-8">
          <FieldSkeleton labelWidth="w-20" valueWidth="w-24" />
          <div className="flex min-w-0 flex-1 flex-col gap-1.5">
            <Skeleton className="h-3 w-28 rounded" />
            <Skeleton className="h-8 w-full max-w-xs rounded-md" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

const RolesCardSkeleton = () => {
  return (
    <Card variant="inner" padding="none" className="gap-4 p-4 md:p-5">
      <CardHeader>
        <div className="flex flex-col gap-1.5">
          <Skeleton className="h-6 w-28 rounded" />
          <Skeleton className="h-3 w-48 rounded" />
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-2">
          <RoleItemSkeleton />
          <RoleItemSkeleton />
        </div>
      </CardContent>
    </Card>
  );
};

// Mirrors <RoleItem>: inner card with role badges and permission rows below.
const RoleItemSkeleton = () => {
  return (
    <Card variant="inner">
      <div className="flex items-center gap-2">
        <Skeleton className="h-5 w-20 rounded-full" />
        <Skeleton className="h-5 w-16 rounded-full" />
      </div>
      <div className="border-border-neutral-primary mt-4 grid grid-cols-1 gap-3 border-t pt-4 md:grid-cols-2">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="flex items-center gap-2">
            <Skeleton className="size-4 rounded-full" />
            <Skeleton className="h-3 w-24 rounded" />
          </div>
        ))}
      </div>
    </Card>
  );
};

const OrganizationsCardSkeleton = () => {
  return (
    <Card variant="inner" padding="none" className="gap-4 p-4 md:p-5">
      <CardHeader>
        <div className="flex flex-col gap-1.5">
          <Skeleton className="h-5 w-32 rounded" />
          <Skeleton className="h-3 w-52 rounded" />
        </div>
        <CardAction>
          <Skeleton className="h-8 w-36 rounded-md" />
        </CardAction>
      </CardHeader>
      <CardContent>
        <div className="border-border-neutral-secondary bg-bg-neutral-secondary flex w-full flex-col gap-4 rounded-[14px] border p-4 shadow-sm">
          <div className="bg-bg-neutral-tertiary border-border-neutral-primary grid h-11 grid-cols-[88px_96px_minmax(0,1fr)_120px_48px] items-center gap-4 rounded-full border px-4">
            <Skeleton className="h-3 w-10 rounded" />
            <Skeleton className="h-3 w-12 rounded" />
            <Skeleton className="h-3 w-12 rounded" />
            <Skeleton className="h-3 w-16 rounded" />
            <span className="sr-only">Actions</span>
          </div>
          {[0, 1].map((i) => (
            <div
              key={i}
              className="grid h-12 grid-cols-[88px_96px_minmax(0,1fr)_120px_48px] items-center gap-4 px-4"
            >
              <Skeleton className="h-5 w-14 rounded-full" />
              <Skeleton className="h-5 w-16 rounded-full" />
              <Skeleton className="h-4 w-40 rounded" />
              <Skeleton className="h-4 w-24 rounded" />
              <Skeleton className="ml-auto size-7 rounded-full" />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

// Label + value pair. `inline` lays them side by side (info fields inside a
// row); otherwise stacked (a standalone field).
const FieldSkeleton = ({
  labelWidth,
  valueWidth,
  inline = false,
}: {
  labelWidth: string;
  valueWidth: string;
  inline?: boolean;
}) => {
  return (
    <div
      className={inline ? "flex items-center gap-2" : "flex flex-col gap-1.5"}
    >
      <Skeleton className={`h-3 ${labelWidth} rounded`} />
      <Skeleton className={`h-4 ${valueWidth} rounded`} />
    </div>
  );
};
