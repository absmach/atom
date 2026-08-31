"use client";

import { Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { AtomGraphqlError, graphqlClient } from "@/lib/graphql/client";

// RFC 5280 revocation reason codes accepted by revokeCertificateV2. The
// order matches the section-5.3.1 registry so the dropdown is scannable.
const REVOCATION_REASONS = [
  "unspecified",
  "key_compromise",
  "ca_compromise",
  "affiliation_changed",
  "superseded",
  "cessation_of_operation",
  "privilege_withdrawn",
] as const;

const REVOKE_MUTATION = `mutation Revoke($in: RevokeCertificateV2Input!) {
  revokeCertificateV2(input: $in) {
    certificate { credentialId status }
    reason
    revokedAt
    idempotentReplay
  }
}`;

export function RevokeCertificateButton({
  credentialId,
}: {
  credentialId: string;
}) {
  const router = useRouter();
  const [reason, setReason] = useState<string>("unspecified");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);

  async function submit() {
    setBusy(true);
    try {
      await graphqlClient({
        query: REVOKE_MUTATION,
        variables: { in: { credentialId, reason } },
      });
      toast.success("Certificate revoked");
      setOpen(false);
      router.refresh();
    } catch (caught) {
      const message =
        caught instanceof AtomGraphqlError
          ? caught.errors.map((entry) => entry.message).join("; ")
          : caught instanceof Error
            ? caught.message
            : "Revoke failed";
      toast.error(message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <Button variant="destructive">Revoke</Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke this certificate?</AlertDialogTitle>
          <AlertDialogDescription>
            This is immediate and idempotent. The certificate stays in the
            ledger with an immutable reason and timestamp, and the issuer's
            CRL/OCSP will start reporting it as revoked.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="grid gap-2 py-2">
          <Label htmlFor="revoke-reason">Reason (RFC 5280)</Label>
          <select
            id="revoke-reason"
            className="h-9 rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          >
            {REVOCATION_REASONS.map((entry) => (
              <option key={entry} value={entry}>
                {entry}
              </option>
            ))}
          </select>
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={(event) => {
              event.preventDefault();
              void submit();
            }}
            disabled={busy}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {busy ? (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            ) : null}
            Revoke {reason}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
