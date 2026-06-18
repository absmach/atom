import type { Metadata } from "next";
import { CrudWorkspace } from "@/components/crud/crud-workspace";

export const metadata: Metadata = { title: "Actions" };

export default async function ActionsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return (
    <div className="grid gap-8">
      <CrudWorkspace resourceKey="capability-actions" searchParams={sp} />
      <CrudWorkspace resourceKey="capabilities" searchParams={sp} />
      <CrudWorkspace resourceKey="action-assignment-rules" searchParams={sp} />
    </div>
  );
}
