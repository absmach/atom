import Link from "next/link";
import { notFound } from "next/navigation";
import { CertificateStatusBadge } from "@/components/pki/badges";
import { PemViewer } from "@/components/pki/pem-viewer";
import { RevokeCertificateButton } from "@/components/pki/revoke-certificate-button";
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

type Certificate = {
  credentialId: string;
  entityId?: string | null;
  tenantId?: string | null;
  issuerId?: string | null;
  serialNumber?: string | null;
  fingerprintSha256?: string | null;
  status: string;
  expiresAt?: string | null;
  createdAt: string;
  certificatePem?: string | null;
  subject?: Record<string, unknown> | null;
  dnsNames?: string[] | null;
  ipAddresses?: string[] | null;
  profileName?: string | null;
  identityUri?: string | null;
  revocationReason?: string | null;
  revokedAt?: string | null;
};

const QUERY = `query PkiCertificate($id: ID!) {
  certificate(credentialId: $id) {
    credentialId entityId tenantId issuerId serialNumber
    fingerprintSha256 status expiresAt createdAt certificatePem
    subject dnsNames ipAddresses profileName identityUri
    revocationReason revokedAt
  }
}`;

export default async function CertificateDetailPage({
  params,
}: {
  params: Promise<{ credentialId: string }>;
}) {
  const { credentialId } = await params;
  let data: { certificate: Certificate | null };
  try {
    data = await graphqlServer<{ certificate: Certificate | null }>({
      query: QUERY,
      variables: { id: credentialId },
    });
  } catch {
    notFound();
  }
  const cert = data.certificate;
  if (!cert) notFound();

  const isRevoked = cert.status === "revoked";

  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-semibold tracking-tight">
            {cert.identityUri ?? cert.serialNumber ?? cert.credentialId}
          </h1>
          <CertificateStatusBadge status={cert.status} />
          {cert.serialNumber ? (
            <Badge variant="outline" className="font-mono">
              serial {cert.serialNumber}
            </Badge>
          ) : null}
        </div>
        <p className="mt-1 font-mono text-xs text-muted-foreground">
          {cert.credentialId}
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Identity</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-2 text-sm">
            <Row label="Entity" value={cert.entityId} mono />
            <Row label="Tenant" value={cert.tenantId} mono />
            <Row label="Issuer" value={cert.issuerId} mono />
            <Row label="Profile" value={cert.profileName} />
            <Row label="Identity URI" value={cert.identityUri} mono />
            <Row
              label="DNS names"
              value={
                cert.dnsNames && cert.dnsNames.length > 0
                  ? cert.dnsNames.join(", ")
                  : null
              }
            />
            <Row
              label="IP addresses"
              value={
                cert.ipAddresses && cert.ipAddresses.length > 0
                  ? cert.ipAddresses.join(", ")
                  : null
              }
            />
            <Row
              label="Fingerprint (SHA-256)"
              value={cert.fingerprintSha256}
              mono
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Lifecycle</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-2 text-sm">
            <Row label="Expires at" value={cert.expiresAt} />
            <Row label="Issued at" value={cert.createdAt} />
            {isRevoked ? (
              <>
                <Row label="Revocation reason" value={cert.revocationReason} />
                <Row label="Revoked at" value={cert.revokedAt} />
              </>
            ) : null}
          </CardContent>
        </Card>

        {cert.subject ? (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Subject</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="max-h-64 overflow-auto rounded-md border bg-muted p-3 font-mono text-xs">
                <code>{JSON.stringify(cert.subject, null, 2)}</code>
              </pre>
            </CardContent>
          </Card>
        ) : null}

        {cert.certificatePem ? (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Certificate (PEM)</CardTitle>
              <CardDescription>
                The issued leaf certificate. Download and inspect with{" "}
                <code className="rounded bg-muted px-1 py-0.5 text-xs">
                  openssl x509 -noout -text
                </code>
                .
              </CardDescription>
            </CardHeader>
            <CardContent>
              <PemViewer
                value={cert.certificatePem}
                filename={`certificate-${cert.serialNumber ?? cert.credentialId}.pem`}
              />
            </CardContent>
          </Card>
        ) : null}
      </div>

      <div className="flex flex-wrap gap-2">
        <Button asChild variant="outline">
          <Link href="/pki/certificates">← Back to certificates</Link>
        </Button>
        {!isRevoked ? (
          <RevokeCertificateButton credentialId={cert.credentialId} />
        ) : null}
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
