"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import FindingsList from "@/components/FindingsList";
import VerdictCard from "@/components/VerdictCard";
import { ApiError, getScan, type ScanResponse } from "@/lib/api";
import { defangUrl } from "@/lib/defang";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string; notFound: boolean }
  | { kind: "done"; scan: ScanResponse };

export default function ScanResultInner() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [state, setState] = useState<State>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    getScan(id)
      .then((scan) => {
        if (!cancelled) setState({ kind: "done", scan });
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        const err = e instanceof ApiError ? e : null;
        setState({
          kind: "error",
          message:
            err?.message ?? "Something went wrong. Please try again.",
          notFound: err?.status === 404,
        });
      });
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (state.kind === "loading") {
    return (
      <div>
        <h1>Checking your scan…</h1>
        <p role="status">Loading the result, please wait.</p>
      </div>
    );
  }

  if (state.kind === "error") {
    return (
      <div>
        <h1>{state.notFound ? "Scan not found" : "Could not load the scan"}</h1>
        <p role="alert">{state.message}</p>
        <p>
          <Link className="btn btn-primary" href="/">
            Check another
          </Link>
        </p>
      </div>
    );
  }

  const { scan } = state;
  return (
    <div>
      <VerdictCard verdict={scan.verdict} riskScore={scan.risk_score} />

      {scan.type === "qr" && (
        <p className="qr-note-box" role="note">
          A QR code is only for PAYING. If someone asks you to scan a QR code
          to RECEIVE money, it is a scam.
        </p>
      )}

      <section aria-label="Summary">
        <h2>What we found</h2>
        <p>{scan.summary}</p>
      </section>

      <section aria-label="Warning signs">
        <h2>Warning signs</h2>
        <FindingsList findings={scan.findings} />
      </section>

      {scan.notes.length > 0 && (
        <section aria-label="Notes">
          <h2>Notes</h2>
          <ul>
            {scan.notes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        </section>
      )}

      {scan.redirect_chain.length > 0 && (
        <section aria-label="Link path">
          <h2>Where this link goes</h2>
          <ol>
            {scan.redirect_chain.map((u, i) => (
              <li key={i}>
                <code className="defanged">{defangUrl(u)}</code>
              </li>
            ))}
          </ol>
        </section>
      )}

      <p className="safety-line">
        A scan only checks signs of risk. It cannot prove something is safe.
      </p>

      <p>
        <Link className="btn btn-primary" href="/">
          Check another
        </Link>
      </p>
    </div>
  );
}
