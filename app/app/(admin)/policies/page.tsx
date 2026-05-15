import type { Metadata } from "next";
import { CrudWorkspace } from "@/components/crud/crud-workspace";

export const metadata: Metadata = { title: "Policy Bindings" };

export default async function PoliciesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return <CrudWorkspace resourceKey="policies" searchParams={sp} />;
}
