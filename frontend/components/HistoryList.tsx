"use client";

import Link from "next/link";
import type { ScanHistoryItem } from "@/lib/api";
import { verdictInfo } from "@/components/VerdictCard";

const TYPE_LABELS: Record<string, string> = {
  url: "Link",
  message: "Message",
  upi: "UPI ID",
  qr: "QR image",
};

export function typeLabel(type: string): string {
  return TYPE_LABELS[type] ?? type;
}

export function formatScanDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return iso;
  }
  return d.toLocaleString();
}

// Presentational history list: rows link to results, plus an empty state.
export default function HistoryList({ items }: { items: ScanHistoryItem[] }) {
  if (items.length === 0) {
    return (
      <div>
        <p>You have no scans yet.</p>
        <p>
          <Link className="btn btn-primary" href="/">
            Check something
          </Link>
        </p>
      </div>
    );
  }
  return (
    <ul className="history-list">
      {items.map((item) => {
        const info = verdictInfo(item.verdict);
        return (
          <li key={item.id} className="history-row">
            <Link
              href={`/scan/${encodeURIComponent(item.id)}`}
              className="history-link"
            >
              <span className="history-type">{typeLabel(item.type)}</span>{" "}
              <span className={`history-verdict ${info.className}`}>
                {info.title}
              </span>
              <span className="history-meta">
                Score {item.risk_score} out of 100 ·{" "}
                {formatScanDate(item.created_at)}
              </span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
