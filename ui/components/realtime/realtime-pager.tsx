import { Button } from "@/components/shadcn/button/button";

interface RealtimePagerProps {
  page: number;
  pages: number;
  count: number;
  disabled?: boolean;
  onPageChange: (page: number) => void;
}

export function RealtimePager({
  page,
  pages,
  count,
  disabled,
  onPageChange,
}: RealtimePagerProps) {
  if (pages <= 1) return null;
  return (
    <nav
      aria-label="Pagination"
      className="flex flex-wrap items-center justify-between gap-2"
    >
      <span className="text-text-neutral-tertiary text-sm">
        Page {page} of {pages} ({count} total)
      </span>
      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={disabled || page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          Previous
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={disabled || page >= pages}
          onClick={() => onPageChange(page + 1)}
        >
          Next
        </Button>
      </div>
    </nav>
  );
}
