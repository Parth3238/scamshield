"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import {
  ApiError,
  approveReport,
  listAdminReports,
  rejectReport,
  type AdminReportOut,
} from "@/lib/api";
import { defangUrl } from "@/lib/defang";

const PAGE_SIZE = 20;

function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return iso;
  }
  return d.toLocaleString();
}

// One pending report. Content and target are plain text only, so any
// HTML typed by a reporter shows as literal text, never as markup.
function ReportCard({
  report,
  busy,
  confirming,
  onAsk,
  onCancel,
  onConfirm,
}: {
  report: AdminReportOut;
  busy: boolean;
  confirming: "approve" | "reject" | null;
  onAsk: (action: "approve" | "reject") => void;
  onCancel: () => void;
  onConfirm: (action: "approve" | "reject") => void;
}) {
  return (
    <li className="key-row">
      <p className="key-meta">
        <strong>Type:</strong> {report.scam_type} ·{" "}
        {formatDateTime(report.created_at)}
      </p>
      <p className="report-content">{report.content}</p>
      {report.reported_value && (
        <p className="key-meta">
          <strong>Target ({report.reported_value_type ?? "link"}):</strong>{" "}
          <span className="defanged">{defangUrl(report.reported_value)}</span>
        </p>
      )}
      {confirming === null ? (
        <p className="key-actions">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => onAsk("approve")}
          >
            Approve
          </button>{" "}
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => onAsk("reject")}
          >
            Reject
          </button>
        </p>
      ) : (
        <p className="key-actions">
          <span>
            {confirming === "approve" ? "Approve" : "Reject"} this report?{" "}
          </span>
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy}
            onClick={() => onConfirm(confirming)}
          >
            {busy
              ? "Working…"
              : confirming === "approve"
                ? "Yes, approve"
                : "Yes, reject"}
          </button>{" "}
          <button
            type="button"
            className="btn btn-ghost"
            disabled={busy}
            onClick={onCancel}
          >
            Cancel
          </button>
        </p>
      )}
    </li>
  );
}

function AdminInner() {
  const [items, setItems] = useState<AdminReportOut[]>([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<{
    id: string;
    action: "approve" | "reject";
  } | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const batch = await listAdminReports("pending", PAGE_SIZE, 0);
        if (cancelled) {
          return;
        }
        setItems(batch);
        setOffset(batch.length);
        setHasMore(batch.length === PAGE_SIZE);
      } catch (e) {
        if (!cancelled) {
          setError(
            e instanceof ApiError
              ? e.message
              : "Could not load reports. Please try again."
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

  async function loadMore() {
    setLoadingMore(true);
    setError(null);
    try {
      const batch = await listAdminReports("pending", PAGE_SIZE, offset);
      setItems((prev) => [...prev, ...batch]);
      setOffset(offset + batch.length);
      setHasMore(batch.length === PAGE_SIZE);
    } catch (e) {
      setError(
        e instanceof ApiError
          ? e.message
          : "Could not load more reports. Please try again."
      );
    } finally {
      setLoadingMore(false);
    }
  }

  async function doReview(id: string, action: "approve" | "reject") {
    setBusyId(id);
    setError(null);
    try {
      if (action === "approve") {
        await approveReport(id);
      } else {
        await rejectReport(id);
      }
      // Remove the reviewed item from the pending list.
      setItems((prev) => prev.filter((r) => r.id !== id));
      setConfirming(null);
    } catch (e) {
      if (
        e instanceof ApiError &&
        e.status === 409 &&
        e.message.includes("already been reviewed")
      ) {
        // Someone else reviewed it first: drop it locally with a note.
        setItems((prev) => prev.filter((r) => r.id !== id));
        setConfirming(null);
        setError(
          "This report has already been reviewed by someone else. It was removed from your list."
        );
      } else {
        setError(
          e instanceof ApiError
            ? e.message
            : "Could not finish this review. Please try again."
        );
      }
    } finally {
      setBusyId(null);
    }
  }

  if (loading) {
    return (
      <div>
        <h1>Review reports</h1>
        <p role="status">Loading pending reports, please wait.</p>
      </div>
    );
  }

  return (
    <div>
      <h1>Review reports</h1>
      <p className="lede">
        Approve real scams so others can see them. Reject mistakes and spam.
      </p>
      {error !== null && (
        <p className="form-error" role="alert" aria-live="assertive">
          {error}
        </p>
      )}
      {items.length === 0 ? (
        <p>No pending reports. Nice work — everything is reviewed.</p>
      ) : (
        <>
          <ul className="key-list">
            {items.map((r) => (
              <ReportCard
                key={r.id}
                report={r}
                busy={busyId === r.id}
                confirming={confirming?.id === r.id ? confirming.action : null}
                onAsk={(action) => setConfirming({ id: r.id, action })}
                onCancel={() => setConfirming(null)}
                onConfirm={(action) => void doReview(r.id, action)}
              />
            ))}
          </ul>
          {hasMore && (
            <p>
              <button
                type="button"
                className="btn btn-primary"
                disabled={loadingMore}
                aria-busy={loadingMore}
                onClick={() => void loadMore()}
              >
                {loadingMore ? "Loading…" : "Load more"}
              </button>
            </p>
          )}
        </>
      )}
    </div>
  );
}

// Only admins may see the queue. Others get a 403-style message.
// (The real protection lives on the backend; this is just convenience.)
export default function AdminView() {
  const { user, loading } = useAuth();

  if (loading) {
    return <p role="status">Loading, please wait.</p>;
  }
  if (user === null || user.role !== "admin") {
    return (
      <div>
        <h1>Not allowed</h1>
        <p className="form-error" role="alert">
          ⛔ You do not have permission to view this page (403). If you are an
          admin, please log in with your admin account.
        </p>
      </div>
    );
  }
  return <AdminInner />;
}
