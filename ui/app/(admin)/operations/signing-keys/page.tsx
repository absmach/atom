import { KeyRound } from "lucide-react";
import type { Metadata } from "next";
import { SigningKeysPage } from "@/components/operations/signing-keys-page";

export const metadata: Metadata = { title: "Signing Keys" };

export default function OperationsSigningKeysPage() {
  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <KeyRound className="size-5 text-primary" />
          <h1 className="text-2xl font-semibold tracking-tight">
            Signing Keys
          </h1>
        </div>
      </div>
      <SigningKeysPage />
    </section>
  );
}
