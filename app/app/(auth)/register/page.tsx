import { ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import { RegisterForm } from "@/components/auth/register-form";

export const metadata: Metadata = { title: "Sign Up" };

import Link from "next/link";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export const dynamic = "force-dynamic";

export default function RegisterPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-muted/30 p-4">
      <div className="w-full max-w-md border rounded-lg p-6 pb-14">
        <h2 className="mt-5 text-center text-2xl font-bold leading-9 tracking-tight">
          Atom
        </h2>
        <p className="text-center font-semibold">Sign Up</p>
        <div className="mt-4">
          <RegisterForm />
        </div>
        <p className="text-center text-sm text-muted-foreground">
          Already have an account?{" "}
          <Link
            href="/login"
            className="font-medium text-primary underline-offset-4 hover:underline"
          >
            Sign in
          </Link>
        </p>
      </div>
    </main>
  );
}
