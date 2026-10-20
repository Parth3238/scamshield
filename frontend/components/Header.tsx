"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useAuth } from "@/lib/auth";

export default function Header() {
  const { user, loading, logout } = useAuth();
  const router = useRouter();
  const [open, setOpen] = useState(false);

  async function onLogout() {
    await logout();
    setOpen(false);
    router.push("/");
  }

  function close() {
    setOpen(false);
  }

  const isAdmin = user !== null && user.role === "admin";
  const loggedIn = user !== null;

  return (
    <header className="site-header">
      <nav className="nav" aria-label="Main navigation">
        <Link href="/" className="brand" onClick={close}>
          ScamShield
        </Link>
        <button
          type="button"
          className="btn btn-ghost nav-toggle"
          aria-expanded={open}
          aria-controls="main-menu"
          aria-label={open ? "Close menu" : "Open menu"}
          onClick={() => setOpen((o) => !o)}
        >
          {open ? "Close" : "Menu"}
        </button>
        <ul
          id="main-menu"
          className={open ? "nav-links nav-open" : "nav-links"}
        >
          <li>
            <Link href="/" onClick={close}>
              Check
            </Link>
          </li>
          <li>
            <Link href="/trending" onClick={close}>
              Trending
            </Link>
          </li>
          <li>
            <Link href="/report" onClick={close}>
              Report
            </Link>
          </li>
          {loggedIn && (
            <li>
              <Link href="/history" onClick={close}>
                History
              </Link>
            </li>
          )}
          {loggedIn && (
            <li>
              <Link href="/dashboard/keys" onClick={close}>
                API keys
              </Link>
            </li>
          )}
          {isAdmin && (
            <li>
              <Link href="/admin" onClick={close}>
                Admin
              </Link>
            </li>
          )}
          <li>
            {loading ? null : loggedIn && user !== null ? (
              <span className="user-chip">
                <span className="user-email">{user.email}</span>{" "}
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => void onLogout()}
                >
                  Logout
                </button>
              </span>
            ) : (
              <Link href="/login" onClick={close}>
                Login
              </Link>
            )}
          </li>
        </ul>
      </nav>
    </header>
  );
}
