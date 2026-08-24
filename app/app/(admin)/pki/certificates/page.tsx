import type { Metadata } from "next";
import { CrudWorkspace } from "@/components/crud/crud-workspace";

export const metadata: Metadata = { title: "PKI Certificates" };

export default async function PkiCertificatesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return <CrudWorkspace resourceKey="pki-certificates" searchParams={sp} />;
}
