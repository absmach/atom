import { Badge } from "@/components/ui/badge";

// Shared badges for the PKI section. Colours mirror the domain semantics
// (active/valid → success, retiring/pending → warning, revoked/failed →
// destructive) rather than the visual weight, so a certificate list scans
// the same way in every table it appears in.

const AUTHORITY_STATUS_VARIANTS: Record<
  string,
  "default" | "secondary" | "destructive" | "outline"
> = {
  active: "secondary",
  provisioning: "outline",
  pending_signature: "outline",
  retiring: "outline",
  retired: "outline",
  revoked: "destructive",
  expired: "destructive",
  failed: "destructive",
};

const AUTHORITY_KIND_LABELS: Record<string, string> = {
  root: "Root",
  platform_intermediate: "Platform Intermediate",
  platform_leaf_issuer: "Platform Leaf Issuer",
  tenant_intermediate: "Tenant Intermediate",
};

const CERT_STATUS_VARIANTS: Record<
  string,
  "default" | "secondary" | "destructive" | "outline"
> = {
  active: "secondary",
  pending: "outline",
  expired: "destructive",
  revoked: "destructive",
};

export function AuthorityStatusBadge({ status }: { status?: string | null }) {
  if (!status) {
    return <Badge variant="outline">unknown</Badge>;
  }
  return (
    <Badge variant={AUTHORITY_STATUS_VARIANTS[status] ?? "outline"}>
      {status}
    </Badge>
  );
}

export function AuthorityKindBadge({ kind }: { kind?: string | null }) {
  if (!kind) {
    return <Badge variant="outline">unknown</Badge>;
  }
  return (
    <Badge variant="outline" title={kind}>
      {AUTHORITY_KIND_LABELS[kind] ?? kind}
    </Badge>
  );
}

export function CertificateStatusBadge({ status }: { status?: string | null }) {
  if (!status) {
    return <Badge variant="outline">unknown</Badge>;
  }
  return (
    <Badge variant={CERT_STATUS_VARIANTS[status] ?? "outline"}>{status}</Badge>
  );
}
