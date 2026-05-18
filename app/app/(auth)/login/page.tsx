import type { Metadata } from "next";
import { LoginForm } from "@/components/auth/login-form";

export const metadata: Metadata = { title: "Sign In" };

export const dynamic = "force-dynamic";

export default function LoginPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-muted/30 p-4">
      <div className="w-full max-w-md border rounded-lg p-6 pb-14">
        <h2 className="mt-5 text-center text-2xl font-bold leading-9 tracking-tight">
          Atom
        </h2>
        <p className="text-center font-semibold">Sign In</p>

        <div className="mt-4">
          <LoginForm />
        </div>
      </div>
    </main>
  );
}
