"use client";

import { useState } from "react";
import { ApiError, SCAM_TYPES, submitReport, type ScamType } from "@/lib/api";

const MIN_LEN = 10;
const MAX_LEN = 2000;

// Report a scam: scam type + description + optional target.
// Success text comes from the backend message; errors are friendly by status.
export default function ReportForm() {
  const [scamType, setScamType] = useState<ScamType>("phishing");
  const [content, setContent] = useState("");
  const [target, setTarget] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const trimmedLen = content.trim().length;
  const remaining = MAX_LEN - content.length;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const text = content.trim();
    if (text.length < MIN_LEN) {
      setError(
        `Please describe what happened in at least ${MIN_LEN} characters (now ${text.length}).`
      );
      return;
    }
    if (content.length > MAX_LEN) {
      setError(
        `That description is too long. Please keep it under ${MAX_LEN} characters.`
      );
      return;
    }
    const cleanTarget = target.trim();
    if (cleanTarget.length > 500) {
      setError("That link or ID is too long (max 500 characters).");
      return;
    }
    setError(null);
    setDone(null);
    setBusy(true);
    try {
      const res = await submitReport({
        scam_type: scamType,
        content: text,
        ...(cleanTarget ? { target: cleanTarget } : {}),
      });
      // Show the backend thanks message word for word, then clear the form.
      setDone(res.message);
      setScamType("phishing");
      setContent("");
      setTarget("");
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : "Something went wrong. Please try again."
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <p className="warn-box" role="note">
        <strong>Stay safe:</strong> Never include passwords, OTPs, card numbers
        or your own phone number.
      </p>
      <form className="check-form" onSubmit={(e) => void onSubmit(e)} noValidate>
        <label className="field-label" htmlFor="report-type">
          Type of scam
        </label>
        <select
          id="report-type"
          className="text-input auth-input"
          value={scamType}
          onChange={(e) => setScamType(e.target.value as ScamType)}
        >
          {SCAM_TYPES.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </select>

        <label className="field-label" htmlFor="report-content">
          What happened?
        </label>
        <textarea
          id="report-content"
          className="text-input"
          rows={5}
          placeholder="e.g. I got a call saying my account will be blocked unless I share an OTP…"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          aria-describedby="report-count"
          required
        />
        <p id="report-count" className="char-count" aria-live="polite">
          {trimmedLen < MIN_LEN
            ? `${MIN_LEN - trimmedLen} more characters needed (minimum ${MIN_LEN}, maximum ${MAX_LEN})`
            : `${remaining} characters left (maximum ${MAX_LEN})`}
        </p>

        <label className="field-label" htmlFor="report-target">
          Suspicious link, domain or UPI ID{" "}
          <span className="optional-tag">(optional)</span>
        </label>
        <input
          id="report-target"
          className="text-input auth-input"
          type="text"
          placeholder="e.g. evil-offer.example or shop@okaxis"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          maxLength={600}
          autoComplete="off"
        />

        {error !== null && (
          <p className="form-error" role="alert" aria-live="assertive">
            {error}
          </p>
        )}
        {done !== null && (
          <p className="info-box" role="status" aria-live="polite">
            {done}
          </p>
        )}
        <button
          type="submit"
          className="btn btn-primary"
          disabled={busy}
          aria-busy={busy}
        >
          {busy ? "Sending…" : "Send report"}
        </button>
      </form>
    </div>
  );
}
