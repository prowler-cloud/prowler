interface CloudFeatureBadgeProps {
  label?: string;
}

export const CloudFeatureBadge = ({
  label = "Available in Prowler Cloud",
}: CloudFeatureBadgeProps) => (
  <span
    className="text-primary-foreground inline-flex h-6 shrink-0 items-center justify-center rounded-lg px-2 text-xs leading-5 font-bold"
    style={{
      backgroundImage:
        "linear-gradient(112deg, rgb(46, 229, 155) 3.5%, rgb(98, 223, 240) 98.8%)",
    }}
  >
    {label}
  </span>
);
