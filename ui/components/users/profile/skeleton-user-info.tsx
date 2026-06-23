import {
  Card,
  CardAction,
  CardContent,
  CardHeader,
  Separator,
  Skeleton,
} from "@/components/shadcn";

// Mirrors the real profile layout (UserBasicInfoCard full-width + a two-column
// grid with RolesCard and Organizations) so the page does not shift when the
// data resolves. Conditional cards (SAML / API keys) depend on permissions not
// known while loading, so we mirror only the always-present structure.
export const SkeletonUserInfo = () => {
  return (
    <div className="flex w-full flex-col gap-6">
      <UserBasicInfoSkeleton />
      <div className="flex flex-col gap-6 xl:flex-row">
        <div className="flex w-full flex-col gap-6 xl:max-w-[50%]">
          <RolesCardSkeleton />
        </div>
        <div className="flex w-full flex-col gap-6 xl:max-w-[50%]">
          <OrganizationsCardSkeleton />
        </div>
      </div>
    </div>
  );
};

const UserBasicInfoSkeleton = () => {
  return (
    <Card variant="base" padding="none" className="p-4">
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
    <Card variant="base" padding="none" className="p-4">
      <CardContent>
        {/* Header: "Active roles" + subtitle */}
        <div className="mb-6 flex flex-col gap-1.5">
          <Skeleton className="h-6 w-28 rounded" />
          <Skeleton className="h-3 w-48 rounded" />
        </div>
        <div className="flex flex-col gap-2">
          <RoleItemSkeleton />
          <RoleItemSkeleton />
        </div>
      </CardContent>
    </Card>
  );
};

// Mirrors <RoleItem>: inner card with a role badge + state on the left, a
// details toggle on the right, and a grid of permission rows below.
const RoleItemSkeleton = () => {
  return (
    <Card variant="inner">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Skeleton className="h-5 w-20 rounded-full" />
          <Skeleton className="h-3 w-16 rounded" />
        </div>
        <Skeleton className="h-5 w-20 rounded" />
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
    <Card variant="base" padding="none" className="p-4">
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
        <div className="flex flex-col gap-2">
          <MembershipItemSkeleton />
          <MembershipItemSkeleton />
        </div>
      </CardContent>
    </Card>
  );
};

// Mirrors <MembershipItem>: role badge (left), Name / Joined fields, and the
// "Active" badge (right).
const MembershipItemSkeleton = () => {
  return (
    <Card variant="inner" className="p-2">
      <div className="flex w-full flex-col gap-2 sm:flex-row sm:items-center sm:gap-4">
        <Skeleton className="h-5 w-16 rounded-full" />
        <div className="flex flex-row flex-wrap gap-1 gap-x-4">
          <FieldSkeleton inline labelWidth="w-10" valueWidth="w-24" />
          <FieldSkeleton inline labelWidth="w-14" valueWidth="w-20" />
        </div>
        <div className="ml-auto">
          <Skeleton className="h-5 w-14 rounded-full" />
        </div>
      </div>
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
