import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

const SUMMARY_IDS = ["h", "e", "t", "r", "p", "ro", "a", "cr"];
const CHART_PAIR_1 = ["entity-mix", "status"];
const CHART_PAIR_2 = ["risk", "resource-kinds"];
const POSTURE_METRICS = ["m1", "m2", "m3", "m4"];
const AUDIT_ROWS = ["r1", "r2", "r3", "r4", "r5"];

export default function Loading() {
  return (
    <div className="grid gap-6">
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {SUMMARY_IDS.map((id) => (
          <Card key={id}>
            <CardHeader className="pb-2">
              <Skeleton className="h-4 w-28" />
              <Skeleton className="mt-3 h-8 w-20" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-4 w-full" />
            </CardContent>
          </Card>
        ))}
      </section>

      <section className="grid gap-4 xl:grid-cols-[1fr_1fr]">
        {CHART_PAIR_1.map((id) => (
          <Card key={id}>
            <CardHeader>
              <Skeleton className="h-5 w-32" />
              <Skeleton className="h-4 w-52" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-72 w-full" />
            </CardContent>
          </Card>
        ))}
      </section>

      <section className="grid gap-4 xl:grid-cols-[1fr_1fr]">
        {CHART_PAIR_2.map((id) => (
          <Card key={id}>
            <CardHeader>
              <Skeleton className="h-5 w-32" />
              <Skeleton className="h-4 w-52" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-72 w-full" />
            </CardContent>
          </Card>
        ))}
      </section>

      <section className="grid gap-4 xl:grid-cols-[420px_1fr]">
        <Card>
          <CardHeader>
            <Skeleton className="h-5 w-44" />
            <Skeleton className="h-4 w-56" />
          </CardHeader>
          <CardContent>
            <div className="grid gap-3">
              <div className="grid grid-cols-2 gap-3">
                {POSTURE_METRICS.map((k) => (
                  <Skeleton key={k} className="h-20 w-full" />
                ))}
              </div>
              <Skeleton className="h-8 w-full" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <Skeleton className="h-5 w-44" />
            <Skeleton className="h-4 w-56" />
          </CardHeader>
          <CardContent>
            <div className="grid gap-3">
              {AUDIT_ROWS.map((k) => (
                <Skeleton key={k} className="h-9 w-full" />
              ))}
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
