import { cn } from "@/lib/utils";

interface StatsContainerProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

const StatsContainer = ({
  className,
  children,
  ...props
}: StatsContainerProps) => {
  return (
    <div
      className={cn(
        "flex rounded-xl border border-slate-200 bg-white px-[19px] py-[9px] dark:border-[rgba(38,38,38,0.7)] dark:bg-[rgba(23,23,23,0.5)] dark:backdrop-blur-[46px]",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
};

export { StatsContainer };
