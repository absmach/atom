import Link from "next/link";
import { notFound } from "next/navigation";
import {
  AuthorityKindBadge,
  AuthorityStatusBadge,
} from "@/components/pki/badges";
import { PemViewer } from "@/components/pki/pem-viewer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { graphqlServer } from "@/lib/graphql/server";

type Authority = {
  id: string;
  kind: string;
  version: number;
  status: string;
  issuanceEnabled: boolean;
  subject: string;
  serialNumber?: string | null;
  fingerprintSha256?: string | null;
  subjectKeyId?: string | null;
  authorityKeyId?: string | null;
  certificatePem?: string | null;
  chainPem?: string | null;
  tenantId?: string | null;
  parentId?: string | null;
  ocspUrl?: string | null;
  caIssuersUrl?: string | null;
  crlDistributionPointUrl?: string | null;
  notBefore?: string | null;
  notAfter?: string | null;
  activatedAt?: string | null;
  retiringAt?: string | null;
  retiredAt?: string | null;
  createdAt: string;
  updatedAt: string;
  failureReason?: string | null;
};

const QUERY = `query PkiAuthority($id: ID!) {
  pkiAuthority(id: $id) {
    id kind version status issuanceEnabled subject serialNumber
    fingerprintSha256 subjectKeyId authorityKeyId certificatePem chainPem
    tenantId parentId ocspUrl caIssuersUrl crlDistributionPointUrl
    notBefore notAfter activatedAt retiringAt retiredAt createdAt updatedAt
    failureReason
  }
}`;

export default async function AuthorityDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  let data: { pkiAuthority: Authority | null };
  try {
    data = await graphqlServer<{ pkiAuthority: Authority | null }>({
      query: QUERY,
      variables: { id },
    });
  } catch {
    notFound();
  }
  const authority = data.pkiAuthority;
  if (!authority) notFound();

  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-semibold tracking-tight">
            {authority.subject}
          </h1>
          <AuthorityKindBadge kind={authority.kind} />
          <AuthorityStatusBadge status={authority.status} />
          <Badge variant="outline">v{authority.version}</Badge>
          {authority.issuanceEnabled ? (
            <Badge variant="secondary">issuance enabled</Badge>
          ) : (
            <Badge variant="outline">issuance disabled</Badge>
          )}
        </div>
        <p className="mt-1 font-mono text-xs text-muted-foreground">
          {authority.id}
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Identity</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-2 text-sm">
            <Row label="Serial number" value={authority.serialNumber} mono />
            <Row
              label="Fingerprint (SHA-256)"
              value={authority.fingerprintSha256}
              mono
            />
            <Row label="Subject key ID" value={authority.subjectKeyId} mono />
            <Row
              label="Authority key ID"
              value={authority.authorityKeyId}
              mono
            />
            <Row label="Tenant" value={authority.tenantId} mono />
            <Row label="Parent" value={authority.parentId} mono />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Lifecycle</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-2 text-sm">
            <Row label="Not before" value={authority.notBefore} />
            <Row label="Not after" value={authority.notAfter} />
            <Row label="Activated at" value={authority.activatedAt} />
            <Row label="Retiring at" value={authority.retiringAt} />
            <Row label="Retired at" value={authority.retiredAt} />
            <Row label="Failure reason" value={authority.failureReason} />
            <Row label="Created" value={authority.createdAt} />
            <Row label="Updated" value={authority.updatedAt} />
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Publication URLs</CardTitle>
            <CardDescription>
              The URLs embedded in every leaf certificate issued by this
              authority. Populated at activation from the deployment's public
              base URL.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-2 text-sm">
            <UrlRow label="OCSP" href={authority.ocspUrl} />
            <UrlRow label="CA Issuers" href={authority.caIssuersUrl} />
            <UrlRow label="CRL" href={authority.crlDistributionPointUrl} />
          </CardContent>
        </Card>

        {authority.certificatePem ? (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Certificate (PEM)</CardTitle>
            </CardHeader>
            <CardContent>
              <PemViewer
                value={authority.certificatePem}
                filename={`authority-${authority.id}.pem`}
              />
            </CardContent>
          </Card>
        ) : null}

        {authority.chainPem ? (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Chain (PEM)</CardTitle>
            </CardHeader>
            <CardContent>
              <PemViewer
                value={authority.chainPem}
                filename={`chain-${authority.id}.pem`}
              />
            </CardContent>
          </Card>
        ) : null}
      </div>

      <div className="flex gap-2">
        <Button asChild variant="outline">
          <Link href="/pki/authorities">← Back to authorities</Link>
        </Button>
        <Button asChild>
          <Link
            href={`/pki/actions?tab=retire-authority&authorityId=${authority.id}`}
          >
            Retire authority
          </Link>
        </Button>
      </div>
    </section>
  );
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value?: string | null;
  mono?: boolean;
}) {
  return (
    <div className="grid grid-cols-[160px_1fr] gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span className={mono ? "break-all font-mono text-xs" : ""}>
        {value || "—"}
      </span>
    </div>
  );
}

function UrlRow({ label, href }: { label: string; href?: string | null }) {
  if (!href) {
    return <Row label={label} value="—" />;
  }
  return (
    <div className="grid grid-cols-[160px_1fr] gap-2">
      <span className="text-muted-foreground">{label}</span>
      <a
        href={href}
        target="_blank"
        rel="noreferrer"
        className="break-all font-mono text-xs underline decoration-dotted hover:decoration-solid"
      >
        {href}
      </a>
    </div>
  );
}
