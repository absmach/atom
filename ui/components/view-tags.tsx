import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export function DisplayTags({
  tags,
  className,
}: {
  tags?: string[];
  className?: string;
}) {
  if (!tags) {
    return null;
  }
  return (
    <div
      className={cn(
        "inline-flex flex-wrap gap-1 max-w-max font-medium",
        className,
      )}
    >
      {tags.map((tag, index) => (
        <Badge
          // biome-ignore lint/suspicious/noArrayIndexKey: Tags are not unique
          key={index}
          variant="secondary"
          className="rounded-sm px-1 font-normal text-xs mx-1"
        >
          {tag}
        </Badge>
      ))}
    </div>
  );
}
