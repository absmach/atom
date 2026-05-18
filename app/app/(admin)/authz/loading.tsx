import {
  Card,
  CardContent,
  CardHeader,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

export default function Loading() {
  return (
    <div className="grid gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Authorization debugger
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Visualize why an Atom authorization decision was allowed or denied.
        </p>
      </div>
      <div className="grid gap-4 xl:grid-cols-[420px_1fr]">
        <Card>
          <CardHeader>
            <Skeleton className="h-5 w-32" />
          </CardHeader>
          <CardContent className="grid gap-4">
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-9 w-full" />
            <div className="flex items-center gap-3">
              <Skeleton className="h-5 w-10" />
              <Skeleton className="h-4 w-40" />
            </div>
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-28 w-full" />
            <div className="flex justify-end">
              <Skeleton className="h-9 w-24" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <Skeleton className="h-5 w-20" />
            <Skeleton className="h-4 w-64" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-48 w-full" />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
