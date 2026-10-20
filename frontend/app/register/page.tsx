"use client";

import Link from "next/link";
import AuthForm from "@/components/AuthForm";

export default function RegisterPage() {
  return (
    <div>
      <h1>Create your account</h1>
      <p className="lede">
        An account keeps your scan history in one place. It is free.
      </p>
      <AuthForm mode="register" />
      <p className="privacy-note">
        Already have an account? <Link href="/login">Log in</Link>.
      </p>
    </div>
  );
}
