import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { SignupForm } from "@/components/auth/signup-form";
import { getRegistrationAvailability } from "@/lib/auth/registration";

export const metadata: Metadata = { title: "Create Account" };

export const dynamic = "force-dynamic";

export default async function RegisterPage() {
  const registration = await getRegistrationAvailability();
  if (!registration.enabled) {
    redirect("/login");
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-muted/30 p-4">
      <div className="w-full max-w-md rounded-lg border bg-background p-6 pb-10">
        <h2 className="mt-5 text-center text-2xl font-bold leading-9 tracking-tight">
          Atom
        </h2>
        <p className="text-center font-semibold">Create account</p>

        <div className="mt-4">
          <SignupForm
            emailVerificationRequired={registration.emailVerificationRequired}
            devAllowUnverifiedEmailLogin={
              registration.devAllowUnverifiedEmailLogin
            }
          />
        </div>

        <p className="mt-6 text-center text-sm text-muted-foreground">
          Already have access?{" "}
          <Link className="font-medium text-foreground underline" href="/login">
            Sign in
          </Link>
        </p>
      </div>
    </main>
  );
}
