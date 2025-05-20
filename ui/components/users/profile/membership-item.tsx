import { Chip } from "@nextui-org/react";

import { DateWithTime } from "@/components/ui/entities";
import { MembershipDetailData } from "@/types/users/users";

export const MembershipItem = ({
  membership,
  tenantName,
}: {
  membership: MembershipDetailData;
  tenantName: string;
}) => (
  <div className="rounded-lg bg-gray-50 p-2 dark:bg-gray-800">
    <div className="flex flex-col space-y-2 sm:flex-row sm:items-center sm:justify-between sm:space-y-0">
      <div className="mb-2 flex items-center gap-2">
        <Chip size="sm" variant="flat" color="secondary">
          {membership.attributes.role}
        </Chip>
        <p className="text-xs font-medium">{tenantName}</p>
      </div>
    </div>
    <div className="flex items-center gap-2 text-xs text-gray-500">
      <span className="">Joined on:</span>
      <DateWithTime inline dateTime={membership.attributes.date_joined} />
    </div>
  </div>
);
