import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { requireResource } from "@/lib/crud/resources";

const SKELETON_ROWS = ["r1", "r2", "r3", "r4", "r5"];

export function CrudWorkspaceLoading({ resourceKey }: { resourceKey: string }) {
  const resource = requireResource(resourceKey);
  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <resource.icon className="size-5 text-primary" />
          <h1 className="text-2xl font-semibold tracking-tight">
            {resource.title}
          </h1>
        </div>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          {resource.description}
        </p>
      </div>
      <div className="grid gap-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <Skeleton className="h-9 w-full sm:w-72" />
            {resource.columns.some((c) => c.key === "status") ? (
              <Skeleton className="h-9 w-full sm:w-40" />
            ) : null}
          </div>
          <div className="flex items-center gap-2">
            <Skeleton className="h-9 w-16" />
            <Skeleton className="h-9 w-24" />
          </div>
        </div>
        <div className="overflow-x-auto rounded-md border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                {resource.columns.map((col) => (
                  <TableHead key={col.key}>{col.label}</TableHead>
                ))}
                <TableHead>
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {SKELETON_ROWS.map((id) => (
                <TableRow key={id}>
                  {resource.columns.map((col) => (
                    <TableCell key={col.key}>
                      <Skeleton className="h-4 w-24" />
                    </TableCell>
                  ))}
                  <TableCell>
                    <Skeleton className="h-8 w-8" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <Skeleton className="h-4 w-16" />
          <div className="flex items-center gap-4">
            <Skeleton className="hidden h-9 w-28 sm:block" />
            <Skeleton className="h-4 w-28" />
            <div className="flex items-center gap-1">
              {["fl", "pr", "nx", "ls"].map((k) => (
                <Skeleton key={k} className="size-8" />
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
