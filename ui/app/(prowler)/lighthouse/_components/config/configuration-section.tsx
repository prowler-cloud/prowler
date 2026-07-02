import { type ReactNode } from "react";

export function ConfigurationSection({
  children,
  description,
  icon,
  title,
}: {
  children: ReactNode;
  description: string;
  icon: ReactNode;
  title: string;
}) {
  return (
    <section className="grid gap-6 md:grid-cols-[220px_minmax(0,1fr)]">
      <div className="flex gap-3">
        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex size-8 shrink-0 items-center justify-center rounded-[8px] border">
          {icon}
        </div>
        <div>
          <h4 className="text-text-neutral-primary text-sm font-semibold">
            {title}
          </h4>
          <p className="text-text-neutral-secondary mt-1 text-sm">
            {description}
          </p>
        </div>
      </div>
      <div className="min-w-0">{children}</div>
    </section>
  );
}
