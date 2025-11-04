interface CustomSectionProps {
  title: string | React.ReactNode;
  children: React.ReactNode;
  action?: React.ReactNode;
}

export const CustomSection = ({
  title,
  children,
  action,
}: CustomSectionProps) => (
  <div className="dark:bg-prowler-blue-400 flex flex-col gap-4 rounded-lg p-4 shadow">
    <div className="flex items-center justify-between">
      <h3 className="text-md dark:text-prowler-theme-pale/90 font-medium text-gray-800">
        {title}
      </h3>
      {action && <div>{action}</div>}
    </div>
    {children}
  </div>
);
