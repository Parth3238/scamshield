"use client";

import { useEffect, useState } from "react";
import RequireAuth from "@/components/RequireAuth";
import {
  ApiError,
  createApiKey,
  getApiKeyUsage,
  listApiKeys,
  revokeApiKey,
  type ApiKeyOut,
  type ApiKeyUsageDay,
  type ApiKeyUsageOut,
} from "@/lib/api";

function limitsText(key: ApiKeyOut): string {
  if (key.limits) {
    return key.limits;
  }
  if (typeof key.daily_limit === "number") {
    return `${key.daily_limit} requests per day`;
  }
  return "Standard limits";
}

function statusText(status: string): string {
  return status === "active" ? "Active" : status === "revoked" ? "Revoked" : status;
}

function formatDateTime(iso: string | null): string {
  if (!iso) {
    return "Never used";
  }
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return iso;
  }
  return d.toLocaleString();
}

// Per-key usage: 14-day bars without any chart library, plus quota left.
function KeyUsagePanel({ keyId }: { keyId: string }) {
  const [usage, setUsage] = useState<ApiKeyUsageOut | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setUsage(await getApiKeyUsage(keyId));
      } catch (e) {
        if (!cancelled) {
          setError(
            e instanceof ApiError
              ? e.message
              : "Could not load usage. Please try again."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [keyId]);

  if (loading) {
    return <p role="status">Loading usage, please wait.</p>;
  }
  if (error !== null) {
    return (
      <p className="form-error" role="alert" aria-live="assertive">
        {error}
      </p>
    );
  }
  if (usage === null) {
    return null;
  }
  const days = Array.isArray((usage as { days?: unknown }).days)
    ? (usage.days as ApiKeyUsageDay[])
    : [];
  const max = Math.max(1, ...days.map((d) => d.count));
  return (
    <div className="usage-panel">
      <p className="usage-quota" aria-live="polite">
        {usage.today_remaining !== null
          ? `Today you have ${usage.today_remaining} requests left${usage.daily_limit !== null ? ` out of ${usage.daily_limit}` : ""}.`
          : "Usage for the last 14 days is shown below."}
      </p>
      <ul className="usage-bars" aria-label="Requests per day for 14 days">
        {days.map((d) => (
          <li key={d.date} className="usage-row">
            <span className="usage-date">{d.date}</span>
            <span
              className="usage-bar"
              role="img"
              aria-label={`${d.date}: ${d.count} requests`}
            >
              <span
                className="usage-fill"
                style={{ width: `${Math.round((d.count / max) * 100)}%` }}
              />
            </span>
            <span className="usage-count">
              {d.count} {d.count === 1 ? "request" : "requests"}
            </span>
          </li>
        ))}
      </ul>
      {days.length === 0 && (
        <p className="char-count">No usage in the last 14 days.</p>
      )}
    </div>
  );
}

function ApiKeysInner() {
  const [keys, setKeys] = useState<ApiKeyOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  // Full key is kept only until the user closes the box, then cleared.
  const [newKey, setNewKey] = useState<{ name: string; fullKey: string } | null>(
    null
  );
  const [copied, setCopied] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const data = await listApiKeys();
        if (!cancelled) {
          setKeys(data);
        }
      } catch (e) {
        if (!cancelled) {
          setError(
            e instanceof ApiError
              ? e.message
              : "Could not load your API keys. Please try again."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    const clean = name.trim();
    if (clean.length < 1 || clean.length > 50) {
      setCreateError("Please give the key a name of 1 to 50 characters.");
      return;
    }
    setCreateError(null);
    setCreating(true);
    try {
      const created = await createApiKey(clean);
      setKeys((prev) => [
        {
          id: created.id,
          name: created.name,
          prefix: created.prefix,
          status: "active",
          last_used: null,
        },
        ...prev,
      ]);
      setNewKey({ name: created.name, fullKey: created.full_key });
      setCopied(false);
      setName("");
    } catch (err) {
      setCreateError(
        err instanceof ApiError
          ? err.message
          : "Could not create the key. Please try again."
      );
    } finally {
      setCreating(false);
    }
  }

  async function onRevoke(id: string) {
    setBusyId(id);
    setActionError(null);
    try {
      await revokeApiKey(id);
      setKeys((prev) =>
        prev.map((k) => (k.id === id ? { ...k, status: "revoked" } : k))
      );
      setConfirmRevoke(null);
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? err.message
          : "Could not revoke the key. Please try again."
      );
    } finally {
      setBusyId(null);
    }
  }

  async function onCopy() {
    if (newKey === null) {
      return;
    }
    try {
      await navigator.clipboard.writeText(newKey.fullKey);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  function closeNewKey() {
    // Forget the secret immediately; it can never be shown again.
    setNewKey(null);
    setCopied(false);
  }

  if (loading) {
    return (
      <div>
        <h1>Your API keys</h1>
        <p role="status">Loading your API keys, please wait.</p>
      </div>
    );
  }

  return (
    <div>
      <h1>Your API keys</h1>
      <p className="lede">
        Keys let your own apps check links with ScamShield. Keep them secret
        like passwords.
      </p>

      {error !== null && (
        <p className="form-error" role="alert" aria-live="assertive">
          {error}
        </p>
      )}

      {newKey !== null && (
        <section className="key-new-box" aria-label="New API key">
          <h2>Copy your new key now</h2>
          <p className="key-warning" role="alert">
            <strong>Warning:</strong> This is the only time you will see this
            key. Copy it now.
          </p>
          <p className="key-full">{newKey.fullKey}</p>
          <p className="key-actions">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void onCopy()}
            >
              {copied ? "Copied ✓" : "Copy"}
            </button>{" "}
            <button
              type="button"
              className="btn btn-ghost"
              onClick={closeNewKey}
            >
              Close
            </button>
          </p>
          {copied && (
            <p className="info-box" role="status">
              Copied. Store it somewhere safe.
            </p>
          )}
        </section>
      )}

      <section aria-label="Create a new API key">
        <h2>New key</h2>
        <form className="check-form" onSubmit={(e) => void onCreate(e)} noValidate>
          <label className="field-label" htmlFor="key-name">
            Key name
          </label>
          <input
            id="key-name"
            className="text-input auth-input"
            type="text"
            placeholder="e.g. My website"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={60}
            required
            aria-describedby="key-name-hint"
          />
          <p id="key-name-hint" className="char-count" aria-live="polite">
            {name.trim().length}/50 characters.
          </p>
          {createError !== null && (
            <p className="form-error" role="alert" aria-live="assertive">
              {createError}
            </p>
          )}
          <button
            type="submit"
            className="btn btn-primary"
            disabled={creating}
            aria-busy={creating}
          >
            {creating ? "Creating…" : "Create key"}
          </button>
        </form>
      </section>

      <section aria-label="Your keys">
        <h2>Your keys ({keys.length})</h2>
        {actionError !== null && (
          <p className="form-error" role="alert" aria-live="assertive">
            {actionError}
          </p>
        )}
        {keys.length === 0 ? (
          <p>You have no API keys yet. Create one above to get started.</p>
        ) : (
          <ul className="key-list">
            {keys.map((k) => (
              <li key={k.id} className="key-row">
                <p className="key-name">
                  <strong>{k.name}</strong>{" "}
                  <span
                    className={
                      k.status === "active"
                        ? "key-status key-active"
                        : "key-status key-revoked"
                    }
                  >
                    {k.status === "active" ? "● " : "○ "}
                    {statusText(k.status)}
                  </span>
                </p>
                <p className="key-meta">
                  Starts with <span className="defanged">{k.prefix}</span> ·{" "}
                  {limitsText(k)} · Last used {formatDateTime(k.last_used)}
                </p>
                <details className="details-box">
                  <summary>See usage (last 14 days)</summary>
                  <KeyUsagePanel keyId={k.id} />
                </details>
                {k.status === "active" &&
                  (confirmRevoke === k.id ? (
                    <p className="key-actions">
                      <span>Revoke this key? It will stop working at once. </span>
                      <button
                        type="button"
                        className="btn btn-primary"
                        disabled={busyId === k.id}
                        onClick={() => void onRevoke(k.id)}
                      >
                        {busyId === k.id ? "Revoking…" : "Yes, revoke"}
                      </button>{" "}
                      <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() => setConfirmRevoke(null)}
                      >
                        Keep it
                      </button>
                    </p>
                  ) : (
                    <p className="key-actions">
                      <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() => setConfirmRevoke(k.id)}
                      >
                        Revoke
                      </button>
                    </p>
                  ))}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-label="How to use your key">
        <h2>How to call the API</h2>
        <p className="char-count">
          Replace <code>YOUR_API_KEY</code> with your own key. This example
          uses a placeholder, not a real key.
        </p>
        <pre className="code-box" aria-label="Example curl command">
{`curl https://scamshield.example/api/scan \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"type": "url", "input": "https://example.com/offer"}'`}
        </pre>
      </section>
    </div>
  );
}

export default function ApiKeysPage() {
  return (
    <RequireAuth>
      <ApiKeysInner />
    </RequireAuth>
  );
}
