import { Chip } from "@heroui/chip";

import { Card, CardContent } from "@/components/shadcn";

import { getAWSIcon, NotificationIcon, SuccessIcon } from "../icons";

interface CardServiceProps {
  fidingsFailed: number;
  serviceAlias: string;
}
export const ServiceCard: React.FC<CardServiceProps> = ({
  fidingsFailed,
  serviceAlias,
}) => {
  return (
    <Card
      role="button"
      tabIndex={0}
      className="bg-bg-neutral-secondary hover:bg-bg-neutral-tertiary w-full cursor-pointer gap-0 shadow-sm transition-colors"
    >
      <CardContent className="flex flex-row items-center justify-between gap-4 p-3">
        <div className="flex items-center gap-4">
          {getAWSIcon(serviceAlias)}
          <div className="flex flex-col">
            <h4 className="text-md leading-5 font-bold">{serviceAlias}</h4>
            <small className="text-default-500">
              {fidingsFailed > 0
                ? `${fidingsFailed} Failed Findings`
                : "No failed findings"}
            </small>
          </div>
        </div>

        <Chip
          className="h-10"
          variant="flat"
          startContent={
            fidingsFailed > 0 ? (
              <NotificationIcon size={18} />
            ) : (
              <SuccessIcon size={18} />
            )
          }
          color={fidingsFailed > 0 ? "danger" : "success"}
          radius="full"
          size="md"
        >
          {fidingsFailed > 0 ? fidingsFailed : ""}
        </Chip>
      </CardContent>
    </Card>
  );
};
