import type { Metadata } from "next";
import { CrudWorkspace } from "@/components/crud/crud-workspace";

export const metadata: Metadata = { title: "Tenant Certificates" };

// Tenant-scoped certificate list. Same resource descriptor as the platform-
// wide /pki/certificates page, but the tenantId is pinned from the route
// parameter so operators (or tenant admins, once the auth model exposes
// them here) see only their tenant's certs. Row-revoke still uses the
// framework's deleteMutation (revokeCertificateV2, reason "unspecified");
// the certificate detail page offers the full reason dropdown.
export default async function TenantCertificatesPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const [{ id }, sp] = await Promise.all([params, searchParams]);
  return (
    <CrudWorkspace
      resourceKey="pki-certificates"
      searchParams={{ ...sp, tenantId: id }}
    />
  );
}
