import type { Metadata } from "next";
import Link from "next/link";
import { LoginForm } from "@/components/auth/login-form";
import { getRegistrationAvailability } from "@/lib/auth/registration";

export const metadata: Metadata = { title: "Sign In" };

export const dynamic = "force-dynamic";

export default async function LoginPage() {
  const registration = await getRegistrationAvailability();

  return (
    <main className="flex min-h-screen items-center justify-center bg-muted/30 p-4">
      <div className="w-full max-w-md rounded-lg border bg-background p-6 pb-10">
        <h2 className="mt-5 text-center text-2xl font-bold leading-9 tracking-tight">
          Atom
        </h2>
        <p className="text-center font-semibold">Sign In</p>

        <div className="mt-4">
          <LoginForm />
        </div>
        {registration.uiRegistrationEnabled && registration.configLoaded ? (
          <RegistrationPrompt enabled={registration.selfRegistrationEnabled} />
        ) : null}
      </div>
    </main>
  );
}

function RegistrationPrompt({ enabled }: { enabled: boolean }) {
  if (!enabled) {
    return (
      <p className="mt-6 text-center text-sm text-muted-foreground">
        Need access? Ask an administrator to onboard you.
      </p>
    );
  }

  return (
    <p className="mt-6 text-center text-sm text-muted-foreground">
      New to Atom?{" "}
      <Link className="font-medium text-foreground underline" href="/register">
        Create account
      </Link>
    </p>
  );
}
