interface CustomSectionProps {
  title: string;
  children: React.ReactNode;
  action?: React.ReactNode;
}

export const CustomSection = ({
  title,
  children,
  action,
}: CustomSectionProps) => (
  <div className="flex flex-col gap-4 rounded-lg p-4 shadow dark:bg-prowler-blue-400">
    <div className="flex items-center justify-between">
      <h3 className="text-md font-medium text-gray-800 dark:text-prowler-theme-pale/90">
        {title}
      </h3>
      {action && <div>{action}</div>}
    </div>
    {children}
  </div>
);
