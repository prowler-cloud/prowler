import { Navbar } from "../nav-bar/navbar";

interface ContentLayoutProps {
  title: string;
  icon: string;
  children: React.ReactNode;
}

export function ContentLayout({ title, icon, children }: ContentLayoutProps) {
  return (
    <div>
      <Navbar title={title} icon={icon} />
      <div className="px-6 py-4 sm:px-8 xl:px-10">{children}</div>
    </div>
  );
}
