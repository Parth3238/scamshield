"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import AuthForm from "@/components/AuthForm";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const { refresh } = useAuth();
  const router = useRouter();

  return (
    <div>
      <h1>Log in</h1>
      <p className="lede">Welcome back. Your history is waiting for you.</p>
      <AuthForm
        mode="login"
        onAuth={() => {
          // Session cookie is set; load the profile, then go home.
          void refresh().then(() => router.push("/"));
        }}
      />
      <p className="privacy-note">
        No account yet? <Link href="/register">Register</Link>.
      </p>
    </div>
  );
}
