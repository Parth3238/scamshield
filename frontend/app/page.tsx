"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import QrUpload from "@/components/QrUpload";
import { ApiError, postScan, type ScanType } from "@/lib/api";

const MAX_LEN = 2048;

type Tab = ScanType | "qr";

const TABS: { id: Tab; label: string; fieldLabel: string; placeholder: string }[] = [
  {
    id: "url",
    label: "Link",
    fieldLabel: "Link to check",
    placeholder: "e.g. https://example.com/some-offer",
  },
  {
    id: "message",
    label: "Message",
    fieldLabel: "Message to check",
    placeholder: "e.g. Your account will be blocked today, update KYC now",
  },
  {
    id: "upi",
    label: "UPI ID",
    fieldLabel: "UPI ID to check",
    placeholder: "e.g. shop@okaxis",
  },
  {
    id: "qr",
    label: "QR image",
    fieldLabel: "QR image to check",
    placeholder: "",
  },
];

export default function Home() {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>("url");
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const active = TABS.find((t) => t.id === tab) ?? TABS[0];
  const remaining = MAX_LEN - input.length;

  async function onCheck() {
    if (tab === "qr") {
      return;
    }
    const text = input.trim();
    if (text.length === 0) {
      setError("Please type or paste something to check first.");
      return;
    }
    if (text.length > MAX_LEN) {
      setError(`That is too long. Please keep it under ${MAX_LEN} characters.`);
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const result = await postScan({ type: tab, input: text });
      router.push(`/scan/${encodeURIComponent(result.scan_id)}`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong. Please try again.");
      setLoading(false);
    }
  }

  return (
    <div>
      <h1>Check a link, message, UPI ID or QR image</h1>
      <p className="lede">
        Paste something suspicious and we will point out the warning signs in
        simple words.
      </p>

      <div className="tabs" role="tablist" aria-label="What to check">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            className={tab === t.id ? "tab tab-active" : "tab"}
            onClick={() => {
              setTab(t.id);
              setError(null);
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "qr" ? (
        <QrUpload />
      ) : (
      <form
        className="check-form"
        onSubmit={(e) => {
          e.preventDefault();
          void onCheck();
        }}
      >
        <label className="field-label" htmlFor="check-input">
          {active.fieldLabel}
        </label>
        <textarea
          id="check-input"
          className="text-input"
          rows={4}
          maxLength={MAX_LEN + 100}
          placeholder={active.placeholder}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          aria-describedby="char-count"
        />
        <p id="char-count" className="char-count" aria-live="polite">
          {remaining} characters left
        </p>
        {error !== null && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <button
          type="submit"
          className="btn btn-primary"
          disabled={loading}
          aria-busy={loading}
        >
          {loading ? "Checking…" : "Check"}
        </button>
      </form>
      )}

      <p className="privacy-note">
        We do not open your links for you to visit. Do not share OTPs or PINs
        with anyone.
      </p>
    </div>
  );
}
