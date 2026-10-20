"use client";

import Link from "next/link";
import { useState } from "react";
import {
  ApiError,
  getMe,
  login,
  register,
  type AuthUser,
} from "@/lib/api";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Shared login/register form. Pages pass onAuth to receive the user after login.
export default function AuthForm({
  mode,
  onAuth,
}: {
  mode: "login" | "register";
  onAuth?: (user: AuthUser) => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [doneMessage, setDoneMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const isLogin = mode === "login";

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const cleanEmail = email.trim();
    if (!EMAIL_RE.test(cleanEmail)) {
      setError("Please enter a valid email address.");
      return;
    }
    if (password.length < 10 || password.length > 128) {
      setError(
        `Password must be 10 to 128 characters (now ${password.length}).`
      );
      return;
    }
    setError(null);
    setBusy(true);
    try {
      if (isLogin) {
        await login({ email: cleanEmail, password });
        onAuth?.(await getMe());
      } else {
        // Show the backend's generic message word for word.
        const res = await register({ email: cleanEmail, password });
        setDoneMessage(res.message);
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && isLogin) {
        // Always the same generic words, whether the email or password was wrong.
        setError("Invalid email or password");
      } else if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="check-form" onSubmit={(e) => void onSubmit(e)} noValidate>
      <label className="field-label" htmlFor="auth-email">
        Email
      </label>
      <input
        id="auth-email"
        className="text-input auth-input"
        type="email"
        autoComplete="email"
        placeholder="e.g. you@example.com"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        required
      />
      <label className="field-label" htmlFor="auth-password">
        Password
      </label>
      <div className="password-row">
        <input
          id="auth-password"
          className="text-input auth-input"
          type={showPassword ? "text" : "password"}
          autoComplete={isLogin ? "current-password" : "new-password"}
          placeholder="Your password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          aria-describedby="password-hint"
        />
        <button
          type="button"
          className="btn btn-ghost"
          aria-pressed={showPassword}
          aria-label={showPassword ? "Hide password" : "Show password"}
          onClick={() => setShowPassword((s) => !s)}
        >
          {showPassword ? "Hide" : "Show"}
        </button>
      </div>
      <p id="password-hint" className="char-count" aria-live="polite">
        Password must be 10 to 128 characters (now {password.length}).
      </p>
      {error !== null && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {doneMessage !== null && (
        <div>
          <p className="info-box" role="status">
            {doneMessage}
          </p>
          <p>
            <Link className="btn btn-primary" href="/login">
              Go to login
            </Link>
          </p>
        </div>
      )}
      {doneMessage === null && (
        <button
          type="submit"
          className="btn btn-primary"
          disabled={busy}
          aria-busy={busy}
        >
          {busy ? "Please wait…" : isLogin ? "Log in" : "Register"}
        </button>
      )}
    </form>
  );
}
