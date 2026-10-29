import { Badge } from "@/components/shadcn/badge/badge";
import { frameworkLabel } from "@/lib/realtime/display";

/** The compliance frameworks a policy enforces, or a note that all checks are in scope. */
export function FrameworkBadges({
  frameworks,
  catalog = [],
}: {
  frameworks: string[];
  catalog?: Array<{ id: string; name: string }>;
}) {
  if (frameworks.length === 0) {
    return <Badge variant="outline">Enforcing: all checks</Badge>;
  }
  return (
    <ul
      className="flex flex-wrap items-center gap-2"
      aria-label="Enforced frameworks"
    >
      {frameworks.map((id) => (
        <li key={id}>
          <Badge variant="tag">{frameworkLabel(id, catalog)}</Badge>
        </li>
      ))}
    </ul>
  );
}
