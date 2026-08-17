import type { Metadata } from "next";
import { CrudWorkspace } from "@/components/crud/crud-workspace";

export const metadata: Metadata = { title: "PKI Authorities" };

export default async function PkiAuthoritiesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return <CrudWorkspace resourceKey="pki-authorities" searchParams={sp} />;
}
